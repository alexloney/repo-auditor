"""Minimal OpenAI-compatible chat client (OpenRouter, OpenAI, vLLM, LM Studio, ...).

It exposes the same `chat(model, messages, tools, format, options)` surface as
`ollama.Client` and returns objects shaped like Ollama's responses (`resp.message.content`,
`resp.message.tool_calls[i].function.name/.arguments`, `resp.done_reason`), so the scanners and
the agent loop work with either backend unchanged. Uses only the standard library.
"""
import json
import logging
import urllib.error
import urllib.request
from types import SimpleNamespace

from ollama._utils import convert_function_to_tool

logger = logging.getLogger(__name__)

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenAIChatClient:
    def __init__(self, base_url: str, api_key: str | None, timeout: float | None = None,
                 extra_headers: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.extra_headers = extra_headers or {}

    # -- public API ---------------------------------------------------------------------

    def chat(self, model: str, messages: list, tools: list | None = None,
             format: dict | None = None, options: dict | None = None):
        options = options or {}
        payload: dict = {"model": model, "messages": self._convert_messages(messages)}
        if "temperature" in options:
            payload["temperature"] = options["temperature"]
        if options.get("num_predict"):
            payload["max_tokens"] = options["num_predict"]
        if tools:
            payload["tools"] = [
                convert_function_to_tool(t).model_dump(exclude_none=True) if callable(t) else t
                for t in tools
            ]
        if format is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": format},
            }

        try:
            data = self._post("/chat/completions", payload)
        except _HttpError as e:
            # Not every model/provider supports response_format; the schema is also in the
            # prompt, so retry once without it rather than failing.
            if format is None or e.status != 400:
                raise RuntimeError(str(e)) from None
            logger.warning("Model rejected response_format (%s); retrying without it", e)
            payload.pop("response_format")
            try:
                data = self._post("/chat/completions", payload)
            except _HttpError as e2:
                raise RuntimeError(str(e2)) from None

        return self._parse_response(data)

    # -- request / response -------------------------------------------------------------

    def _post(self, path: str, payload: dict) -> dict:
        headers = {"Content-Type": "application/json", "X-Title": "repo-auditor", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            self.base_url + path, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise _HttpError(e.code, _error_text(e.read())) from None
        except urllib.error.URLError as e:
            raise RuntimeError(f"could not reach {self.base_url}: {e.reason}") from None

        # OpenRouter can report upstream failures inside a 200 response.
        if isinstance(data, dict) and data.get("error"):
            err = data["error"]
            raise _HttpError(err.get("code", 0) if isinstance(err, dict) else 0, _error_text(json.dumps(data)))
        return data

    @staticmethod
    def _parse_response(data: dict):
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError(f"response contained no choices: {json.dumps(data)[:300]}")
        choice = choices[0]
        msg = choice.get("message") or {}

        tool_calls = []
        for call in msg.get("tool_calls") or []:
            fn = call.get("function") or {}
            args = fn.get("arguments") or {}
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args.strip() else {}
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append(SimpleNamespace(
                id=call.get("id"),
                function=SimpleNamespace(name=fn.get("name"), arguments=args),
            ))

        message = SimpleNamespace(
            role="assistant",
            content=msg.get("content") or "",
            thinking=msg.get("reasoning") or None,
            tool_calls=tool_calls or None,
        )
        # Reasoning tokens count against max_tokens, so they explain completions cut off by length.
        usage = data.get("usage") or {}
        details = usage.get("completion_tokens_details") or {}
        return SimpleNamespace(message=message, done_reason=choice.get("finish_reason") or "unknown",
                               completion_tokens=usage.get("completion_tokens"),
                               reasoning_tokens=details.get("reasoning_tokens"))

    # -- message conversion -------------------------------------------------------------

    @staticmethod
    def _convert_messages(messages: list) -> list:
        """Converts Ollama-style history to OpenAI format (tool-call ids, JSON-string arguments).

        Tool results in the history only carry `tool_name`, so they're paired with the
        preceding assistant tool calls by name, in order.
        """
        def get(m, key):
            return m.get(key) if isinstance(m, dict) else getattr(m, key, None)

        out = []
        pending: list[tuple[str, str]] = []  # (call id, function name) awaiting a result
        counter = 0
        for m in messages:
            role = get(m, "role")
            content = get(m, "content") or ""
            if role == "assistant" and get(m, "tool_calls"):
                calls = []
                for call in get(m, "tool_calls"):
                    counter += 1
                    call_id = getattr(call, "id", None) or f"call_{counter}"
                    name = call.function.name
                    pending.append((call_id, name))
                    calls.append({
                        "id": call_id,
                        "type": "function",
                        "function": {"name": name, "arguments": json.dumps(call.function.arguments)},
                    })
                out.append({"role": "assistant", "content": content or None, "tool_calls": calls})
            elif role == "tool":
                name = get(m, "tool_name")
                idx = next((i for i, (_, n) in enumerate(pending) if n == name), 0 if pending else None)
                call_id = pending.pop(idx)[0] if idx is not None else "call_unknown"
                out.append({"role": "tool", "tool_call_id": call_id, "content": content})
            else:
                out.append({"role": role, "content": content})
        return out


class _HttpError(Exception):
    def __init__(self, status: int, text: str):
        super().__init__(f"HTTP {status}: {text}")
        self.status = status if isinstance(status, int) else 0


def _error_text(raw: bytes | str) -> str:
    text = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
    try:
        err = json.loads(text).get("error")
        if isinstance(err, dict):
            return str(err.get("message") or err)
        if err:
            return str(err)
    except (ValueError, AttributeError):
        pass
    return text[:500]
