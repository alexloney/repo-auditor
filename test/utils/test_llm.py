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
    assert estimate_tokens("") == 0
    # Rounds up, so even one character costs a token
    assert estimate_tokens("x") == 1
    assert estimate_tokens("def hello(): pass") == 6  # 17 chars / 3, rounded up

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