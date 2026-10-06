import json
import logging
import math
import os
import threading
import time

logger = logging.getLogger(__name__)

MAX_CONTEXT = int(os.getenv("MAX_CONTEXT", "66000"))
OUTPUT_RESERVE = int(os.getenv("OUTPUT_RESERVE", "10000"))

# Line-numbered source code measures ~3.7 chars/token on average (as low as ~2.8 for dense
# files) with a cl100k-style BPE tokenizer. Dividing by 3 deliberately over-counts on average,
# because under-counting overflows num_ctx and Ollama then silently truncates the prompt.
# A character heuristic also keeps the tool fully offline (no tokenizer download).
CHARS_PER_TOKEN = 3

def estimate_tokens(text: str) -> int:
    """Conservative token estimate for budget checks; errs on the side of over-counting."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)

def input_budget() -> int:
    return MAX_CONTEXT - OUTPUT_RESERVE

# How often the main thread wakes while waiting on a request, i.e. the worst-case Ctrl+C delay.
_INTERRUPT_POLL_SECONDS = 0.2

def interruptible_chat(client, **kwargs):
    """Calls client.chat(**kwargs) so that Ctrl+C takes effect immediately.

    A blocking socket read can't be interrupted by Ctrl+C (notably on Windows), so a plain
    client.chat() only notices the interrupt once Ollama finishes generating. Instead, the
    request runs on a daemon thread while the main thread waits in short, interruptible steps.
    On Ctrl+C the KeyboardInterrupt is raised here straight away; the abandoned request dies
    with the process, and dropping its connection makes Ollama stop generating.
    """
    outcome: dict = {}

    def worker():
        try:
            outcome["response"] = client.chat(**kwargs)
        except BaseException as e:  # handed back to the caller's thread below
            outcome["error"] = e

    thread = threading.Thread(target=worker, name="ollama-request", daemon=True)
    thread.start()
    while thread.is_alive():
        thread.join(_INTERRUPT_POLL_SECONDS)

    if "error" in outcome:
        raise outcome["error"]
    return outcome["response"]

def call_json(client, model: str, system: str, user: str, schema: dict, retries: int = 3) -> dict:
    """Calls the LLM with a JSON schema response format, retrying on transient failures."""
    # Ollama's `format` only constrains the output's shape; the model never sees the schema's
    # field descriptions unless they're in the prompt too (as Ollama's docs recommend).
    system = (
        f"{system}\n\nRespond with a JSON object matching this JSON schema, following each "
        f"field's description:\n{json.dumps(schema)}"
    )
    prompt_tokens = estimate_tokens(system) + estimate_tokens(user)
    if prompt_tokens > input_budget():
        raise RuntimeError(
            f"prompt is ~{prompt_tokens} tokens, over the {input_budget()} input budget "
            f"(num_ctx {MAX_CONTEXT} minus {OUTPUT_RESERVE} reserved for output)"
        )

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            resp = interruptible_chat(
                client,
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                format=schema,
                # Retries nudge temperature upward; at 0.0 a retry is deterministic and
                # would reproduce the same empty/invalid completion every time.
                options={
                    "temperature": 0.0 + 0.2 * (attempt - 1),
                    "num_ctx": MAX_CONTEXT,
                    "num_predict": OUTPUT_RESERVE,
                },
            )
            raw = (resp.message.content or "").strip()
            if not raw:
                raise ValueError(
                    f"model returned an empty completion "
                    f"(done_reason={getattr(resp, 'done_reason', 'unknown')}, prompt ~{prompt_tokens} tokens)"
                )
            return json.loads(_strip_json_fence(raw))
        except Exception as e:
            last_err = e
            logger.warning("call_json attempt %d/%d failed: %s", attempt, retries, e)
            if attempt < retries:
                time.sleep(2 * attempt)
    raise RuntimeError(f"call_json failed after {retries} tries: {last_err}")

def _strip_json_fence(raw: str) -> str:
    """Unwraps a ```json ... ``` fence some models emit despite structured-output mode."""
    if raw.startswith("```"):
        newline = raw.find("\n")
        if newline != -1:
            raw = raw[newline + 1:]
        if raw.rstrip().endswith("```"):
            raw = raw.rstrip()[:-3]
    return raw.strip()