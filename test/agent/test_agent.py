import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from auditor.agent.agent import (
    _message_parts,
    _history_digest,
    _compact_history,
    run_agent_loop,
    MAX_CONSECUTIVE_ERRORS,
    MAX_CONSECUTIVE_EMPTY
)

# --- 1. Fixtures & Helpers ---

class DummyFunction:
    def __init__(self, name, arguments):
        self.name = name
        self.arguments = arguments

class DummyToolCall:
    def __init__(self, name, arguments):
        self.function = DummyFunction(name, arguments)

def make_mock_call(name, args):
    """Creates a concrete dummy object so dicts are never converted to strings."""
    return DummyToolCall(name, args)

def make_mock_response(content="", tool_calls=None, done_reason="stop"):
    """Helper to generate a mock Ollama response."""
    msg = MagicMock()
    msg.role = "assistant"
    msg.content = content
    msg.tool_calls = tool_calls or []
    
    resp = MagicMock()
    resp.message = msg
    resp.done_reason = done_reason
    return resp

@pytest.fixture
def agent_setup(tmp_path):
    """Provides standard callbacks, dummy tools, and a mock client."""
    callbacks = {
        "on_progress": MagicMock(),
        "on_warning": MagicMock(),
        "on_error": MagicMock()
    }
    
    def dummy_tool(x: str):
        return f"Tool executed with {x}"
        
    return tmp_path, callbacks, [dummy_tool], MagicMock()

# --- 2. History & Token Management Tests ---

def test_message_parts():
    """Ensures it extracts data correctly from both dicts and objects."""
    # Dict format
    dict_msg = {"role": "user", "content": "hello", "tool_calls": []}
    role, content, calls = _message_parts(dict_msg)
    assert role == "user" and content == "hello" and calls == []

    # Object format
    obj_msg = MagicMock(role="assistant", content="world", tool_calls=[])
    role, content, calls = _message_parts(obj_msg)
    assert role == "assistant" and content == "world"

def test_history_digest():
    """Verifies that the raw message list is condensed into a readable bulleted log."""
    messages = [
        {"role": "user", "content": "Do a thing."},
        MagicMock(role="assistant", content="Thinking...", tool_calls=[]),
        MagicMock(role="assistant", content="", tool_calls=[make_mock_call("read_file", {"filepath": "app.py"})]),
    ]
    
    digest = _history_digest(messages)
    
    assert "- noted: Thinking..." in digest
    assert "read_file" in digest
    assert "app.py" in digest
    assert "Do a thing." not in digest  # User prompts are stripped from the action log

def test_compact_history_success():
    """Verifies that the history compactor uses the LLM to generate a summary."""
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(content="- Checked app.py\n- Needs more review.")
    
    messages = [
        {"role": "user", "content": "Start"},
        MagicMock(role="assistant", content="Noted", tool_calls=[])
    ]
    
    compacted = _compact_history(mock_client, "model", "SYS_PROMPT", messages)
    
    assert len(compacted) == 2
    assert compacted[0]["role"] == "system"
    assert "Checked app.py" in compacted[1]["content"]

# --- 3. Agent Execution Loop Tests ---

def test_run_agent_loop_immediate_stop(agent_setup):
    """Verifies the agent exits cleanly if it issues the stop token immediately."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    mock_client.chat.return_value = make_mock_response(content="Nothing to do. AUDIT_COMPLETE")
    
    run_agent_loop(mock_client, "model", tmp_path, tmp_path / "ledger.json", "sys", "user", tools, **callbacks)
    
    # Executed exactly 1 turn
    assert mock_client.chat.call_count == 1
    callbacks["on_progress"].assert_any_call("Agent: Nothing to do. AUDIT_COMPLETE")

def test_run_agent_loop_tool_execution(agent_setup):
    """Verifies the agent loops, executes a tool, captures the output, and then stops."""
    tmp_path, callbacks, tools, mock_client = agent_setup

    # Pass a dict instead of a raw JSON string
    mock_client.chat.side_effect = [
        make_mock_response(tool_calls=[make_mock_call("dummy_tool", {"x": "test"})]),
        make_mock_response(content="Got it. AUDIT_COMPLETE")
    ]

    run_agent_loop(mock_client, "model", tmp_path, tmp_path / "ledger.json", "sys", "user", tools, **callbacks)

    assert mock_client.chat.call_count == 2
    callbacks["on_progress"].assert_any_call(" > Executing: dummy_tool({'x': 'test'})")

    # Check that the tool result was appended to the messages before the second call
    second_call_messages = mock_client.chat.call_args_list[1][1]["messages"]
    assert second_call_messages[-1]["role"] == "tool"
    assert second_call_messages[-1]["content"] == "Tool executed with test"

def test_run_agent_loop_max_turns(agent_setup):
    """Verifies the loop cuts off automatically if the agent gets stuck in a loop."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    # Always outputs conversational text without the stop token
    mock_client.chat.return_value = make_mock_response(content="Still looking...")
    
    run_agent_loop(mock_client, "model", tmp_path, tmp_path / "ledger.json", "sys", "user", tools, max_turns=3, **callbacks)
    
    assert mock_client.chat.call_count == 3
    callbacks["on_warning"].assert_called_with("Reached the 3-turn limit; ending scan.")

# --- 4. Resilience & Error Recovery Tests ---

def test_run_agent_loop_api_crashes(agent_setup):
    """Verifies that consecutive API failures gracefully abort the scan."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    # The API throws exceptions repeatedly
    mock_client.chat.side_effect = Exception("Connection Refused")
    
    run_agent_loop(mock_client, "model", tmp_path, tmp_path / "ledger.json", "sys", "user", tools, **callbacks)
    
    assert mock_client.chat.call_count == MAX_CONSECUTIVE_ERRORS
    callbacks["on_error"].assert_called_with("Giving up on this scan; findings so far are already saved.")

@patch(f"{run_agent_loop.__module__}._compact_history")
def test_run_agent_loop_empty_completions(mock_compact, agent_setup):
    """Verifies that empty completions trigger history compaction and eventually abort if unrecoverable."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    # The model repeatedly returns empty strings (e.g., done_reason=length)
    mock_client.chat.return_value = make_mock_response(content="", done_reason="length")
    
    # Mock the compactor so it doesn't try to make its own LLM calls during the failure loop
    mock_compact.return_value = [{"role": "system", "content": "sys"}]
    
    run_agent_loop(mock_client, "model", tmp_path, tmp_path / "ledger.json", "sys", "user", tools, **callbacks)
    
    # The chat API is called exactly 3 times before giving up
    assert mock_client.chat.call_count == MAX_CONSECUTIVE_EMPTY
    callbacks["on_warning"].assert_called_with("Agent stopped producing output; ending scan.")
    
    # The compactor is called to recover from the 1st and 2nd failures, but skipped on the final fatal 3rd failure
    assert mock_compact.call_count == MAX_CONSECUTIVE_EMPTY - 1