import pytest
from unittest.mock import MagicMock, patch

from auditor.agent.agent import (
    ConversationContext,
    _execute_tools,
    _chat_with_retries,
    run_agent_loop,
    MAX_CONSECUTIVE_ERRORS,
    MAX_CONSECUTIVE_EMPTY,
    LoopOutcome,
)
from auditor.agent.coverage import ReadCoverage

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

@pytest.fixture
def mock_ctx():
    """Provides a mocked ConversationContext for testing isolated functions."""
    ctx = MagicMock(spec=ConversationContext)
    ctx.client = MagicMock()
    ctx.model = "test-model"
    ctx.get_payload.return_value = [{"role": "system", "content": "sys"}]
    return ctx

# --- 2. ConversationContext Tests ---

def test_context_initialization():
    """Verifies the context sets up the initial system and user prompts."""
    ctx = ConversationContext(MagicMock(), "model", "System Prompt", "User Prompt")
    payload = ctx.get_payload()
    
    assert len(payload) == 2
    assert payload[0] == {"role": "system", "content": "System Prompt"}
    assert payload[1] == {"role": "user", "content": "User Prompt"}

def test_context_append_and_extend():
    """Verifies that new messages can be added to the history."""
    ctx = ConversationContext(MagicMock(), "model", "sys", "user")
    
    ctx.append({"role": "assistant", "content": "Thinking..."})
    assert len(ctx.get_payload()) == 3
    
    ctx.extend([{"role": "tool", "content": "Result"}])
    assert len(ctx.get_payload()) == 4

def test_context_token_estimation():
    """Verifies that token math evaluates properly without crashing."""
    ctx = ConversationContext(MagicMock(), "model", "sys", "user")
    ctx.append({"role": "assistant", "content": "A standard response.", "tool_calls": [make_mock_call("read", {"file": "a"})]})
    
    tokens = ctx.token_count
    assert isinstance(tokens, int)
    assert tokens > 0

def test_context_compaction():
    """Verifies that context successfully calls the LLM to summarize and resets its state."""
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(content="- Reviewed auth.py")
    
    ctx = ConversationContext(mock_client, "model", "SYS", "USER")
    ctx.append({"role": "assistant", "content": "Did some things."})
    
    ctx.compact()
    
    payload = ctx.get_payload()
    assert len(payload) == 2
    assert payload[0]["role"] == "system"
    assert "Reviewed auth.py" in payload[1]["content"]

# --- 3. Agent Execution Loop Tests ---

def test_run_agent_loop_immediate_stop(agent_setup):
    """Verifies the agent exits cleanly if it issues the stop token immediately."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    mock_client.chat.return_value = make_mock_response(content="Nothing to do. AUDIT_COMPLETE")
    
    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, **callbacks)
    
    assert outcome == LoopOutcome.COMPLETED
    assert mock_client.chat.call_count == 1
    callbacks["on_progress"].assert_any_call("Agent: Nothing to do. AUDIT_COMPLETE")

def test_run_agent_loop_tool_execution(agent_setup):
    """Verifies the agent loops, executes a tool, captures the output, and then stops."""
    tmp_path, callbacks, tools, mock_client = agent_setup

    mock_client.chat.side_effect = [
        make_mock_response(tool_calls=[make_mock_call("dummy_tool", {"x": "test"})]),
        make_mock_response(content="Got it. AUDIT_COMPLETE")
    ]

    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, **callbacks)

    assert mock_client.chat.call_count == 2
    callbacks["on_progress"].assert_any_call(" > Executing: dummy_tool({'x': 'test'})")

    second_call_messages = mock_client.chat.call_args_list[1][1]["messages"]
    assert second_call_messages[-1]["role"] == "tool"
    assert second_call_messages[-1]["content"] == "Tool executed with test"

def test_run_agent_loop_max_turns(agent_setup):
    """Verifies the loop cuts off automatically if the agent gets stuck in a loop."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    mock_client.chat.return_value = make_mock_response(content="Still looking...")
    
    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, max_turns=3, **callbacks)
    
    assert outcome == LoopOutcome.TURN_LIMIT
    assert mock_client.chat.call_count == 3
    callbacks["on_warning"].assert_called_with("Reached the 3-turn limit; stopping.")

def test_run_agent_loop_is_done_callback(agent_setup):
    """Verifies the loop stops as soon as is_done() reports True after a tool round."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    done = []
    def finish(x: str):
        done.append(x)
        return "ok"

    mock_client.chat.return_value = make_mock_response(tool_calls=[make_mock_call("finish", {"x": "y"})])

    outcome = run_agent_loop(mock_client, "model", "sys", "user", [finish],
                             stop_token=None, is_done=lambda: bool(done), **callbacks)

    assert outcome == LoopOutcome.COMPLETED
    assert mock_client.chat.call_count == 1

def test_run_agent_loop_custom_nudge_and_no_stop_token(agent_setup):
    """With stop_token=None, plain text never ends the loop and the custom nudge is sent."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    mock_client.chat.return_value = make_mock_response(content="AUDIT_COMPLETE")

    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, stop_token=None,
                             nudge_message="Call the tool.", max_turns=2, **callbacks)

    assert outcome == LoopOutcome.TURN_LIMIT
    second_call_messages = mock_client.chat.call_args_list[1][1]["messages"]
    assert second_call_messages[-1] == {"role": "user", "content": "Call the tool."}

def test_run_agent_loop_retries_do_not_consume_turns(agent_setup):
    """A failed request is retried without using up one of the max_turns."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    mock_client.chat.side_effect = [
        Exception("blip"),
        make_mock_response(content="Done. AUDIT_COMPLETE"),
    ]

    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, max_turns=1, **callbacks)

    assert outcome == LoopOutcome.COMPLETED

def test_compaction_keeps_task_and_coverage():
    """The post-compaction message restates the original task and the tracked coverage."""
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(content="- Looked around")
    coverage = ReadCoverage()
    coverage.record_full("src/a.py")

    ctx = ConversationContext(mock_client, "model", "SYS", "Verify finding X", coverage)
    ctx.append({"role": "assistant", "content": "Did some things."})
    ctx.compact()

    continuation = ctx.get_payload()[1]["content"]
    assert "Verify finding X" in continuation
    assert "- src/a.py (full)" in continuation

# --- 4. Resilience & Error Recovery Tests ---

def test_run_agent_loop_api_crashes(agent_setup):
    """Verifies that consecutive API failures gracefully abort the scan."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    mock_client.chat.side_effect = Exception("Connection Refused")
    
    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, **callbacks)
    
    assert outcome == LoopOutcome.ABORTED
    assert mock_client.chat.call_count == MAX_CONSECUTIVE_ERRORS
    callbacks["on_error"].assert_called_with("Giving up after repeated request failures.")

@patch("auditor.agent.agent.ConversationContext.compact")
def test_run_agent_loop_empty_completions(mock_compact, agent_setup):
    """Verifies that empty completions trigger history compaction and eventually abort if unrecoverable."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    
    mock_client.chat.return_value = make_mock_response(content="", done_reason="length")
    
    outcome = run_agent_loop(mock_client, "model", "sys", "user", tools, **callbacks)
    
    assert mock_client.chat.call_count == MAX_CONSECUTIVE_EMPTY
    callbacks["on_warning"].assert_called_with("Agent stopped producing output; giving up.")
    assert mock_compact.call_count == MAX_CONSECUTIVE_EMPTY - 1

# --- 5. Extracted Helper Tests ---

def test_execute_tools_success():
    """Verifies that valid tools are executed and their results are formatted correctly."""
    def dummy_add(a, b):
        return a + b
    
    available = {"dummy_add": dummy_add}
    calls = [make_mock_call("dummy_add", {"a": 2, "b": 3})]
    mock_progress = MagicMock()
    
    results = _execute_tools(calls, available, mock_progress)
    
    assert len(results) == 1
    assert results[0]["role"] == "tool"
    assert results[0]["tool_name"] == "dummy_add"
    assert results[0]["content"] == "5"
    mock_progress.assert_called_once_with(" > Executing: dummy_add({'a': 2, 'b': 3})")

def test_execute_tools_exception():
    """Verifies that tool crashes are caught and returned to the LLM as error strings."""
    def crash_tool():
        raise ValueError("Something broke")
        
    available = {"crash_tool": crash_tool}
    calls = [make_mock_call("crash_tool", {})]
    
    results = _execute_tools(calls, available, MagicMock())
    
    assert "Execution error: Something broke" in results[0]["content"]

def test_execute_tools_not_found():
    """Verifies behavior when the LLM hallucinates a tool that doesn't exist."""
    available = {}
    calls = [make_mock_call("fake_tool", {})]
    
    results = _execute_tools(calls, available, MagicMock())
    
    assert "Error: Tool fake_tool not found" in results[0]["content"]

def test_chat_with_retries_success(mock_ctx):
    """Verifies a successful chat call returns 'success' and resets error tracking."""
    mock_ctx.client.chat.return_value = make_mock_response(content="Valid output")
    error_state = {"errors": 2, "empty": 2}
    
    msg, status = _chat_with_retries(mock_ctx, [], error_state, MagicMock(), MagicMock())
    
    assert status == "success"
    assert error_state["errors"] == 0
    assert error_state["empty"] == 0
    assert msg.content == "Valid output"
    mock_ctx.compact.assert_not_called()

def test_chat_with_retries_api_error_retry(mock_ctx):
    """Verifies an API crash triggers a retry and context compaction."""
    mock_ctx.client.chat.side_effect = Exception("Timeout")
    error_state = {"errors": 0, "empty": 0}
    
    msg, status = _chat_with_retries(mock_ctx, [], error_state, MagicMock(), MagicMock())
    
    assert status == "retry"
    assert error_state["errors"] == 1
    mock_ctx.compact.assert_called_once()

def test_chat_with_retries_api_error_abort(mock_ctx):
    """Verifies that consecutive API crashes eventually abort the loop."""
    mock_ctx.client.chat.side_effect = Exception("Timeout")
    error_state = {"errors": MAX_CONSECUTIVE_ERRORS - 1, "empty": 0}
    mock_error_cb = MagicMock()
    
    msg, status = _chat_with_retries(mock_ctx, [], error_state, MagicMock(), mock_error_cb)
    
    assert status == "abort"
    assert error_state["errors"] == MAX_CONSECUTIVE_ERRORS
    mock_error_cb.assert_called_once()

def test_chat_with_retries_empty_retry(mock_ctx):
    """Verifies an empty LLM response triggers a retry and context compaction."""
    mock_ctx.client.chat.return_value = make_mock_response(content="", tool_calls=[])
    error_state = {"errors": 0, "empty": 0}
    
    msg, status = _chat_with_retries(mock_ctx, [], error_state, MagicMock(), MagicMock())
    
    assert status == "retry"
    assert error_state["empty"] == 1
    mock_ctx.compact.assert_called_once()

def test_chat_with_retries_empty_abort(mock_ctx):
    """Verifies that consecutive empty responses eventually abort the loop."""
    mock_ctx.client.chat.return_value = make_mock_response(content="", tool_calls=[])
    error_state = {"errors": 0, "empty": MAX_CONSECUTIVE_EMPTY - 1}
    mock_warn_cb = MagicMock()
    
    msg, status = _chat_with_retries(mock_ctx, [], error_state, mock_warn_cb, MagicMock())
    
    assert status == "abort"
    assert error_state["empty"] == MAX_CONSECUTIVE_EMPTY
    assert mock_warn_cb.call_count == 2
def test_context_token_count_is_incremental_and_counts_thinking():
    """token_count tracks appends without re-tokenizing, and includes reasoning text."""
    ctx = ConversationContext(MagicMock(), "model", "sys", "user")
    before = ctx.token_count

    msg = MagicMock()
    msg.role, msg.content, msg.tool_calls = "assistant", "", []
    msg.thinking = "x" * 300
    ctx.append(msg)

    assert ctx.token_count == before + 100  # 300 chars / 3

    with patch("auditor.agent.agent.estimate_tokens") as mock_estimate:
        _ = ctx.token_count
        mock_estimate.assert_not_called()

def test_context_token_count_resets_on_compaction():
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(content="- summary")
    ctx = ConversationContext(mock_client, "model", "sys", "user")
    ctx.append({"role": "assistant", "content": "y" * 3000})

    ctx.compact()

    assert ctx.token_count == sum(ctx._estimate_message(m) for m in ctx.get_payload())

def test_run_agent_loop_ctrl_c_propagates(agent_setup):
    """Ctrl+C is not turned into a scan outcome; it stops the whole run."""
    tmp_path, callbacks, tools, mock_client = agent_setup
    mock_client.chat.side_effect = KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_agent_loop(mock_client, "model", "sys", "user", tools, **callbacks)
    assert mock_client.chat.call_count == 1
