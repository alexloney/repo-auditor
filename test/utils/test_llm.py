import pytest
from unittest.mock import patch, MagicMock

from auditor.utils.llm import (
    estimate_tokens,
    input_budget,
    _strip_json_fence,
    call_json,
    MAX_CONTEXT,
    OUTPUT_RESERVE
)

def test_estimate_tokens():
    # Verify tiktoken is correctly encoding and returning a positive integer
    assert estimate_tokens("def hello(): pass") > 0

def test_input_budget():
    assert input_budget() == MAX_CONTEXT - OUTPUT_RESERVE

def test_strip_json_fence():
    raw_json = '{"issue": "memory leak"}'
    
    # Standard string (no fence)
    assert _strip_json_fence(raw_json) == raw_json
    
    # Standard markdown fence
    fenced = f"```json\n{raw_json}\n```"
    assert _strip_json_fence(fenced) == raw_json
    
    # Markdown fence with trailing whitespace
    fenced_spaces = f"```\n{raw_json}\n```   "
    assert _strip_json_fence(fenced_spaces) == raw_json

# Patch sleep globally for this test class/file so we don't delay the test suite
@patch("auditor.utils.llm.time.sleep")
def test_call_json_success(mock_sleep):
    mock_client = MagicMock()
    # Simulate a successful JSON return on the first try
    mock_client.chat.return_value.message.content = '```json\n{"status": "ok"}\n```'
    
    result = call_json(
        client=mock_client, 
        model="qwen-coder-64k", 
        system="sys", 
        user="user", 
        schema={"type": "object"}
    )
    
    assert result == {"status": "ok"}
    mock_client.chat.assert_called_once()
    mock_sleep.assert_not_called()

def test_call_json_budget_exceeded():
    mock_client = MagicMock()
    # Create a string large enough to guarantee it blows past the 56k budget limit
    massive_string = "token " * (MAX_CONTEXT + 1)
    
    with pytest.raises(RuntimeError, match="over the .* input budget"):
        call_json(mock_client, "model", "sys", massive_string, {})
        
    mock_client.chat.assert_not_called()

@patch("auditor.utils.llm.time.sleep")
def test_call_json_retries_and_succeeds(mock_sleep):
    mock_client = MagicMock()
    
    # Configure the mock to raise two exceptions, then return a valid response
    mock_client.chat.side_effect = [
        Exception("Connection reset"),
        Exception("Timeout"),
        MagicMock(message=MagicMock(content='{"status": "recovered"}'))
    ]
    
    result = call_json(mock_client, "model", "sys", "user", {})
    
    assert result == {"status": "recovered"}
    assert mock_client.chat.call_count == 3
    
    # Verify the exponential backoff sleep was triggered twice
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(2)  # attempt 1 * 2
    mock_sleep.assert_any_call(4)  # attempt 2 * 2

@patch("auditor.utils.llm.time.sleep")
def test_call_json_empty_completion_exhausts_retries(mock_sleep, capsys):
    mock_client = MagicMock()
    
    # Simulate the LLM continuously returning empty strings (e.g., done_reason=length)
    mock_client.chat.return_value.message.content = "   "
    mock_client.chat.return_value.done_reason = "length"
    
    with pytest.raises(RuntimeError, match="call_json failed after 3 tries: model returned an empty completion"):
        call_json(mock_client, "model", "sys", "user", {}, retries=3)
        
    assert mock_client.chat.call_count == 3
    
    # Clear the captured print output so it doesn't pollute the pytest terminal
    capsys.readouterr()
@patch("auditor.utils.llm.time.sleep")
def test_call_json_puts_schema_in_system_prompt(mock_sleep):
    mock_client = MagicMock()
    mock_client.chat.return_value.message.content = '{"findings": []}'
    schema = {"type": "object", "properties": {"x": {"type": "string", "description": "UNIQUE-HINT"}}}

    call_json(mock_client, "m", "SYSTEM", "USER", schema)

    system_msg = mock_client.chat.call_args.kwargs["messages"][0]["content"]
    assert system_msg.startswith("SYSTEM")
    assert "UNIQUE-HINT" in system_msg
    assert mock_client.chat.call_args.kwargs["format"] == schema

def test_interruptible_chat_returns_response_and_passes_kwargs():
    from auditor.utils.llm import interruptible_chat
    client = MagicMock()
    client.chat.return_value = "RESPONSE"

    assert interruptible_chat(client, model="m", messages=[]) == "RESPONSE"
    client.chat.assert_called_once_with(model="m", messages=[])

def test_interruptible_chat_reraises_request_errors():
    from auditor.utils.llm import interruptible_chat
    client = MagicMock()
    client.chat.side_effect = ConnectionError("refused")

    with pytest.raises(ConnectionError, match="refused"):
        interruptible_chat(client, model="m")

def test_interruptible_chat_ctrl_c_does_not_wait_for_the_request():
    """Ctrl+C must land while the request is still blocked, not when it returns."""
    import _thread, threading, time
    from auditor.utils.llm import interruptible_chat
    release = threading.Event()
    client = MagicMock()
    client.chat.side_effect = lambda **kw: release.wait(30)  # a long, blocked request

    threading.Timer(0.3, _thread.interrupt_main).start()  # simulated Ctrl+C
    start = time.monotonic()
    try:
        with pytest.raises(KeyboardInterrupt):
            interruptible_chat(client, model="m")
        assert time.monotonic() - start < 5
    finally:
        release.set()  # let the abandoned worker thread finish

@patch("auditor.utils.llm.time.sleep")
def test_call_json_does_not_retry_on_ctrl_c(mock_sleep):
    mock_client = MagicMock()
    mock_client.chat.side_effect = KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        call_json(mock_client, "m", "s", "u", {"type": "object"})
    assert mock_client.chat.call_count == 1
