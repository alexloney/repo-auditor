import os
from pathlib import Path
from typing import Callable
from auditor.utils.llm import MAX_CONTEXT, OUTPUT_RESERVE, estimate_tokens

CONTEXT_SAFETY_MARGIN = 0.6
MAX_HISTORY_MESSAGES = 200
MAX_CONSECUTIVE_EMPTY = 3
MAX_CONSECUTIVE_ERRORS = 3

class ConversationContext:
    """Encapsulates message history, token estimation, and context compaction."""
    
    def __init__(self, client, model: str, system_prompt: str, initial_user_prompt: str):
        self.client = client
        self.model = model
        self.system_prompt = system_prompt
        self.messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_user_prompt},
        ]
        self.safety_margin = 0.6
        self.max_history = 200

    @property
    def token_count(self) -> int:
        total = 0
        for m in self.messages:
            _, content, calls = self._message_parts(m)
            total += estimate_tokens(content)
            for call in calls:
                total += estimate_tokens(str(call))
        return total

    @property
    def is_full(self) -> bool:
        threshold = (MAX_CONTEXT - OUTPUT_RESERVE) * self.safety_margin
        return len(self.messages) > self.max_history or self.token_count > threshold

    def append(self, message) -> None:
        self.messages.append(message)

    def extend(self, messages) -> None:
        self.messages.extend(messages)

    def get_payload(self) -> list:
        return self.messages

    def compact(self) -> None:
        """Summarizes the action log to free up context window space."""
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
                print(f"    ! History summarization failed, falling back to raw action log: {e}")

        if not summary:
            summary = digest or "(no actions recorded)"

        continuation = (
            "Your conversation history was compacted to save memory. Your reported issues are safely "
            f"saved to disk. Here is a summary of your progress so far:\n\n{summary}\n\n"
            "Continue the audit from here, avoiding files you've already covered."
        )

        self.messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": continuation},
        ]

    def _message_parts(self, m) -> tuple:
        if isinstance(m, dict):
            return m.get("role", ""), (m.get("content") or ""), (m.get("tool_calls") or [])
        return getattr(m, "role", ""), (getattr(m, "content", "") or ""), (getattr(m, "tool_calls", None) or [])

    def _history_digest(self, max_entries: int = 120) -> str:
        lines = []
        for m in self.messages:
            role, content, calls = self._message_parts(m)
            for call in calls:
                lines.append(f"- called {call.function.name}({call.function.arguments})")
            if role == "assistant" and content.strip() and not calls:
                lines.append(f"- noted: {content.strip()[:200]}")
        return "\n".join(lines[-max_entries:])

def _compaction_threshold() -> float:
    return (MAX_CONTEXT - OUTPUT_RESERVE) * CONTEXT_SAFETY_MARGIN

def _message_parts(m):
    if isinstance(m, dict):
        return m.get("role", ""), (m.get("content") or ""), (m.get("tool_calls") or [])
    return getattr(m, "role", ""), (getattr(m, "content", "") or ""), (getattr(m, "tool_calls", None) or [])

def _conversation_tokens(messages) -> int:
    total = 0
    for m in messages:
        _role, content, calls = _message_parts(m)
        total += estimate_tokens(content)
        # Tool-call messages carry empty content but their arguments still cost tokens.
        for call in calls:
            total += estimate_tokens(str(call))
    return total

def _history_digest(messages, max_entries: int = 120) -> str:
    """Condenses the conversation into a short action log of tool calls and agent notes."""
    lines = []
    for m in messages:
        role, content, calls = _message_parts(m)
        for call in calls:
            lines.append(f"- called {call.function.name}({call.function.arguments})")
        if role == "assistant" and content.strip() and not calls:
            lines.append(f"- noted: {content.strip()[:200]}")
    return "\n".join(lines[-max_entries:])

def _compact_history(client, model: str, system_prompt: str, messages: list) -> list:
    """Summarizes progress from a small digest, then rebuilds a short history around it.

    The digest matters: summarizing the raw history would resend the very payload that
    overflowed the context, reproducing the failure it is meant to fix.
    """
    digest = _history_digest(messages)
    summary = ""
    if digest:
        try:
            response = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
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
            print(f"    ! History summarization failed, falling back to the raw action log: {e}")

    if not summary:
        summary = digest or "(no actions recorded)"

    continuation = (
        "Your conversation history was compacted to save memory. Your reported issues are safely "
        f"saved to disk. Here is a summary of your progress so far:\n\n{summary}\n\n"
        "Continue the audit from here, avoiding files you've already covered."
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": continuation},
    ]

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
            on_error("Giving up on this scan; findings so far are already saved.")
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
            on_warning("Agent stopped producing output; ending scan.")
            return None, "abort"
        
        ctx.compact()
        return None, "retry"

    error_state["empty"] = 0
    return msg, "success"

def run_agent_loop(
    client,
    model: str,
    target_dir: Path,
    ledger_path: Path,
    system_prompt: str,
    initial_user_prompt: str,
    tools: list,
    stop_token: str = "AUDIT_COMPLETE",
    max_turns: int = 50,
    on_progress: Callable[[str], None] = None,
    on_warning: Callable[[str], None] = None,
    on_error: Callable[[str], None] = None
) -> None:
    """Drives a tool-calling agent against target_dir until it emits stop_token or runs out of turns."""
    original_dir = os.getcwd()
    os.chdir(target_dir)

    ctx = ConversationContext(client, model, system_prompt, initial_user_prompt)
    available_tools = {t.__name__: t for t in tools}
    error_state = {"errors": 0, "empty": 0}

    on_progress(f"Booting agent loop with {model}...")

    try:
        for _turn in range(max_turns):
            if ctx.is_full:
                ctx.compact()

            msg, status = _chat_with_retries(ctx, tools, error_state, on_warning, on_error)

            if status == "abort":
                break
            if status == "retry":
                continue

            if getattr(msg, "tool_calls", None):
                ctx.append(msg)
                tool_results = _execute_tools(msg.tool_calls, available_tools, on_progress)
                ctx.extend(tool_results)
            else:
                content = (msg.content or "").strip()
                on_progress(f"Agent: {content}")
                
                if stop_token in content:
                    break
                
                ctx.append(msg)
                ctx.append({
                    "role": "user",
                    "content": f"Continue the audit, or reply {stop_token} if you are done.",
                })
        else:
            on_warning(f"Reached the {max_turns}-turn limit; ending scan.")

    except KeyboardInterrupt:
        on_warning("Aborted by user.")
    finally:
        os.chdir(original_dir)