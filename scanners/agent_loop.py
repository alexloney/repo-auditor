"""Reusable tool-calling agent loop shared by the agentic ("pull model") scanners."""
import os
from pathlib import Path

from .common import MAX_CONTEXT, OUTPUT_RESERVE, estimate_tokens

# Compact history once the conversation gets this close to the model's context
# window; past this point completions start coming back truncated/empty and
# the next request can fail with "no user query found in messages".
CONTEXT_SAFETY_MARGIN = 0.75
MAX_HISTORY_MESSAGES = 200
# An exhausted or finished agent emits empty completions; give it a couple of
# chances to recover after a compaction before concluding the scan.
MAX_CONSECUTIVE_EMPTY = 3


def _conversation_tokens(messages) -> int:
    total = 0
    for m in messages:
        if isinstance(m, dict):
            content = m.get("content") or ""
            calls = m.get("tool_calls") or []
        else:
            content = getattr(m, "content", "") or ""
            calls = getattr(m, "tool_calls", None) or []
        total += estimate_tokens(content)
        # Tool-call messages carry empty content but their arguments still cost tokens.
        for call in calls:
            total += estimate_tokens(str(call))
    return total


def _compact_history(client, model: str, system_prompt: str, messages: list) -> list:
    """Asks the model to summarize its own progress, then rebuilds a short history around that summary."""
    summary_request = messages + [{
        "role": "user",
        "content": (
            "Context is running low. Summarize your progress so far in a few concise bullet points: "
            "which directories/files you've already explored, which still need to be examined, and "
            "any suspicious areas worth revisiting. Do not call any tools, reply with plain text only."
        ),
    }]
    summary = ""
    try:
        response = client.chat(
            model=model,
            messages=summary_request,
            options={"temperature": 0.0, "num_ctx": MAX_CONTEXT},
        )
        summary = (response.message.content or "").strip()
    except Exception as e:
        print(f"    ! History summarization failed, falling back to a hard reset: {e}")

    if not summary:
        continuation = (
            "Your conversation history was cleared to save memory. Your reported issues are safely "
            "saved to disk. Continue exploring."
        )
    else:
        continuation = (
            "Your conversation history was compacted to save memory. Your reported issues are safely "
            f"saved to disk. Here is a summary of your progress so far:\n\n{summary}\n\n"
            "Continue the audit from here, avoiding files you've already covered."
        )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": continuation},
    ]


def run_agent_loop(
    client,
    model: str,
    target_dir: Path,
    ledger_path: Path,
    system_prompt: str,
    initial_user_prompt: str,
    tools: list,
    label: str,
    stop_token: str = "AUDIT_COMPLETE",
    max_turns: int = 50,
) -> None:
    """Drives a tool-calling agent against target_dir until it emits stop_token or runs out of turns."""
    original_dir = os.getcwd()
    os.chdir(target_dir)
    # report_issue reads this env var to know where to append findings.
    os.environ["AUDIT_LEDGER_PATH"] = str(ledger_path)

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": initial_user_prompt},
    ]
    available_tools = {t.__name__: t for t in tools}

    print(f"  [{label}] Booting agent loop with {model}...")

    try:
        consecutive_empty = 0
        for _turn in range(max_turns):
            if (len(messages) > MAX_HISTORY_MESSAGES
                    or _conversation_tokens(messages) > MAX_CONTEXT * CONTEXT_SAFETY_MARGIN):
                messages = _compact_history(client, model, system_prompt, messages)

            response = client.chat(
                model=model,
                messages=messages,
                tools=tools,
                options={
                    "temperature": 0.0,
                    "num_ctx": MAX_CONTEXT,
                    "num_predict": OUTPUT_RESERVE,
                },
            )

            msg = response.message

            if not getattr(msg, "tool_calls", None):
                content = (msg.content or "").strip()

                if not content:
                    consecutive_empty += 1
                    reason = getattr(response, "done_reason", "unknown")
                    print(f"  [{label}] Empty completion ({consecutive_empty}/{MAX_CONSECUTIVE_EMPTY}, done_reason={reason})")
                    if consecutive_empty >= MAX_CONSECUTIVE_EMPTY:
                        print(f"  [{label}] Agent stopped producing output; ending scan.")
                        break
                    # Most often the context is exhausted, so reclaim room and retry.
                    messages = _compact_history(client, model, system_prompt, messages)
                    continue

                consecutive_empty = 0
                print(f"  Agent: {content}")
                if stop_token in content:
                    break
                messages.append(msg)
                # Keep the conversation ending on a user turn so the next request is well-formed.
                messages.append({
                    "role": "user",
                    "content": f"Continue the audit, or reply {stop_token} if you are done.",
                })
                continue

            consecutive_empty = 0
            messages.append(msg)

            for call in msg.tool_calls:
                func_name = call.function.name
                args = call.function.arguments

                print(f"    > Executing: {func_name}({args})")

                if func_name in available_tools:
                    try:
                        result = available_tools[func_name](**args)
                    except Exception as e:
                        result = f"Execution error: {e}"
                else:
                    result = f"Error: Tool {func_name} not found."

                messages.append({
                    "role": "tool",
                    "content": str(result),
                    "name": func_name,
                })
        else:
            print(f"  [{label}] Reached the {max_turns}-turn limit; ending scan.")

    except KeyboardInterrupt:
        print(f"\n  [{label}] Aborted by user.")
    finally:
        os.chdir(original_dir)
