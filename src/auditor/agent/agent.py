import logging
from enum import Enum
from typing import Callable
from auditor.utils.llm import MAX_CONTEXT, OUTPUT_RESERVE, estimate_tokens
from auditor.agent.coverage import ReadCoverage

CONTEXT_SAFETY_MARGIN = 0.6
MAX_HISTORY_MESSAGES = 200
MAX_CONSECUTIVE_EMPTY = 3
MAX_CONSECUTIVE_ERRORS = 3
DEFAULT_MAX_TURNS = 100

logger = logging.getLogger(__name__)

class LoopOutcome(str, Enum):
    COMPLETED = "completed"      # stop token emitted or is_done() returned True
    TURN_LIMIT = "turn_limit"    # ran out of turns
    ABORTED = "aborted"          # too many consecutive request failures / empty completions
    INTERRUPTED = "interrupted"  # Ctrl+C

class ConversationContext:
    """Encapsulates message history, token estimation, and context compaction."""

    def __init__(self, client, model: str, system_prompt: str, initial_user_prompt: str,
                 coverage: ReadCoverage | None = None):
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.initial_user_prompt = initial_user_prompt
        self.coverage = coverage
        self.safety_margin = CONTEXT_SAFETY_MARGIN
        self.max_history = MAX_HISTORY_MESSAGES
        self.messages: list = []
        self._token_count = 0
        self.extend([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_user_prompt},
        ])

    @property
    def token_count(self) -> int:
        # Maintained incrementally by append/extend/compact, so the history is never re-tokenized.
        return self._token_count

    def _estimate_message(self, m) -> int:
        _, content, calls = self._message_parts(m)
        total = estimate_tokens(content)
        # Thinking models' reasoning is sent back with the assistant message, so it costs context too.
        total += estimate_tokens(self._get(m, "thinking") or "")
        # Tool-call messages carry empty content but their arguments still cost tokens.
        for call in calls:
            total += estimate_tokens(str(call))
        return total

    @property
    def is_full(self) -> bool:
        threshold = (MAX_CONTEXT - OUTPUT_RESERVE) * self.safety_margin
        return len(self.messages) > self.max_history or self.token_count > threshold

    def append(self, message) -> None:
        self.messages.append(message)
        self._token_count += self._estimate_message(message)

    def extend(self, messages) -> None:
        for message in messages:
            self.append(message)

    def get_payload(self) -> list:
        return self.messages

    def compact(self) -> None:
        """Summarizes progress from a small digest, then rebuilds a short history around it.

        The digest matters: summarizing the raw history would resend the very payload that
        overflowed the context, reproducing the failure it is meant to fix.
        """
        digest = self._history_digest()
        summary = ""

        if digest:
            try:
                response = self.client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": (
                            "Context is running low, so your history is being compacted. Below is the log "
                            "of actions you have taken so far.\n\n"
                            f"{digest}\n\n"
                            "Summarize in a few concise bullet points: which directories/files you have "
                            "already examined, what still needs review, and any suspicious areas worth "
                            "revisiting. Do not call any tools; reply with plain text only."
                        )},
                    ],
                    options={"temperature": 0.0, "num_ctx": MAX_CONTEXT, "num_predict": OUTPUT_RESERVE},
                )
                summary = (response.message.content or "").strip()
            except Exception as e:
                logger.warning("History summarization failed, falling back to raw action log: %s", e)

        if not summary:
            summary = digest or "(no actions recorded)"

        # The coverage list comes from the read tools themselves, so unlike the summary
        # it is exact and can't be lost or hallucinated by the model.
        coverage_section = ""
        if self.coverage is not None and len(self.coverage):
            coverage_section = (
                "Files you have already read (tracked automatically):\n"
                f"{self.coverage.summary()}\n\n"
            )

        continuation = (
            "Your conversation history was compacted to save memory. Anything you already "
            "reported or submitted is safely saved.\n\n"
            f"Your original task:\n{self.initial_user_prompt}\n\n"
            f"Summary of your progress so far:\n{summary}\n\n"
            f"{coverage_section}"
            "Continue from here, avoiding files you've already covered unless you need to "
            "re-check something specific."
        )

        self.messages = []
        self._token_count = 0
        self.extend([
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": continuation},
        ])

    @staticmethod
    def _get(m, key):
        """Reads a field from either a plain dict message or an ollama Message object."""
        return m.get(key) if isinstance(m, dict) else getattr(m, key, None)

    def _message_parts(self, m) -> tuple:
        return self._get(m, "role") or "", self._get(m, "content") or "", self._get(m, "tool_calls") or []

    def _history_digest(self, max_entries: int = 120) -> str:
        """Condenses the conversation into a short action log of tool calls and agent notes."""
        lines = []
        for m in self.messages:
            role, content, calls = self._message_parts(m)
            for call in calls:
                lines.append(f"- called {call.function.name}({call.function.arguments})")
            if role == "assistant" and content.strip() and not calls:
                lines.append(f"- noted: {content.strip()[:200]}")
        return "\n".join(lines[-max_entries:])

def _execute_tools(tool_calls: list, available_tools: dict, on_progress: Callable[[str], None]) -> list:
    """Executes a list of tool calls and returns the resulting message dictionaries."""
    results = []
    for call in tool_calls:
        func_name = call.function.name
        args = call.function.arguments

        on_progress(f" > Executing: {func_name}({args})")

        if func_name in available_tools:
            try:
                result_str = str(available_tools[func_name](**args))
            except Exception as e:
                result_str = f"Execution error: {e}"
        else:
            result_str = f"Error: Tool {func_name} not found."

        results.append({
            "role": "tool",
            "content": result_str,
            "tool_name": func_name,
        })
    return results

def _chat_with_retries(
    ctx: ConversationContext, tools: list, error_state: dict,
    on_warning: Callable[[str], None], on_error: Callable[[str], None]
):
    """
    Attempts an LLM chat call, handling API errors and empty completions.
    Returns a tuple of (msg, status). Status is "success", "retry", or "abort".
    """
    try:
        response = ctx.client.chat(
            model=ctx.model,
            messages=ctx.get_payload(),
            tools=tools,
            options={
                "temperature": 0.0,
                "num_ctx": MAX_CONTEXT,
                "num_predict": OUTPUT_RESERVE,
            },
        )
    except Exception as e:
        error_state["errors"] += 1
        on_warning(f"Chat request failed ({error_state['errors']}/{MAX_CONSECUTIVE_ERRORS}): {e}")
        if error_state["errors"] >= MAX_CONSECUTIVE_ERRORS:
            on_error("Giving up after repeated request failures.")
            return None, "abort"

        ctx.compact()
        return None, "retry"

    error_state["errors"] = 0
    msg = response.message

    if not getattr(msg, "tool_calls", None) and not (msg.content or "").strip():
        error_state["empty"] += 1
        reason = getattr(response, "done_reason", "unknown")
        on_warning(f"Empty completion ({error_state['empty']}/{MAX_CONSECUTIVE_EMPTY}, done_reason={reason})")
        if error_state["empty"] >= MAX_CONSECUTIVE_EMPTY:
            on_warning("Agent stopped producing output; giving up.")
            return None, "abort"

        ctx.compact()
        return None, "retry"

    error_state["empty"] = 0
    return msg, "success"

def run_agent_loop(
    client,
    model: str,
    system_prompt: str,
    initial_user_prompt: str,
    tools: list,
    stop_token: str | None = "AUDIT_COMPLETE",
    is_done: Callable[[], bool] | None = None,
    nudge_message: str | None = None,
    max_turns: int = DEFAULT_MAX_TURNS,
    coverage: ReadCoverage | None = None,
    on_progress: Callable[[str], None] = None,
    on_warning: Callable[[str], None] = None,
    on_error: Callable[[str], None] = None
) -> LoopOutcome:
    """Drives a tool-calling agent until it finishes or runs out of turns.

    The loop finishes when the agent replies with `stop_token` in plain text, or when
    `is_done()` returns True after a round of tool calls (e.g. a verdict tool was called).
    Plain-text replies that don't finish the loop are answered with `nudge_message`.

    Only successful model responses count as turns; retries after request failures or
    empty completions are bounded separately by MAX_CONSECUTIVE_ERRORS / MAX_CONSECUTIVE_EMPTY.
    """
    on_progress = on_progress or (lambda _: None)
    on_warning = on_warning or (lambda _: None)
    on_error = on_error or (lambda _: None)
    if nudge_message is None:
        nudge_message = f"Continue the audit, or reply {stop_token} if you are done."

    ctx = ConversationContext(client, model, system_prompt, initial_user_prompt, coverage)
    available_tools = {t.__name__: t for t in tools}
    error_state = {"errors": 0, "empty": 0}

    on_progress(f"Booting agent loop with {model}...")

    try:
        turns = 0
        while turns < max_turns:
            if ctx.is_full:
                ctx.compact()

            msg, status = _chat_with_retries(ctx, tools, error_state, on_warning, on_error)

            if status == "abort":
                return LoopOutcome.ABORTED
            if status == "retry":
                continue
            turns += 1

            if getattr(msg, "tool_calls", None):
                ctx.append(msg)
                tool_results = _execute_tools(msg.tool_calls, available_tools, on_progress)
                ctx.extend(tool_results)
                if is_done is not None and is_done():
                    return LoopOutcome.COMPLETED
            else:
                content = (msg.content or "").strip()
                on_progress(f"Agent: {content}")

                if stop_token and stop_token in content:
                    return LoopOutcome.COMPLETED

                ctx.append(msg)
                ctx.append({"role": "user", "content": nudge_message})

        on_warning(f"Reached the {max_turns}-turn limit; stopping.")
        return LoopOutcome.TURN_LIMIT

    except KeyboardInterrupt:
        on_warning("Aborted by user.")
        return LoopOutcome.INTERRUPTED
