import tiktoken
import os
import json
import time

MAX_CONTEXT = int(os.getenv("MAX_CONTEXT", "66000"))
OUTPUT_RESERVE = int(os.getenv("OUTPUT_RESERVE", "10000"))

def estimate_tokens(text: str) -> int:
    enc = tiktoken.get_encoding("cl100k_base")
    return len(enc.encode(text))

def input_budget() -> int:
    return MAX_CONTEXT - OUTPUT_RESERVE

def call_json(client, model: str, system: str, user: str, schema: dict, retries: int = 3) -> dict:
    """Calls the LLM with a JSON schema response format, retrying on transient failures."""
    prompt_tokens = estimate_tokens(system) + estimate_tokens(user)
    if prompt_tokens > input_budget():
        raise RuntimeError(
            f"prompt is ~{prompt_tokens} tokens, over the {input_budget()} input budget "
            f"(num_ctx {MAX_CONTEXT} minus {OUTPUT_RESERVE} reserved for output)"
        )

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            resp = client.chat(
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
            print(f"    call_json attempt {attempt}/{retries} failed: {e}")
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