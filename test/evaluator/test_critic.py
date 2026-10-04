import pytest
from unittest.mock import MagicMock
from pathlib import Path

from auditor.evaluator.critic import verify_findings

# --- Helper to generate mock LLM responses ---
def make_mock_response(tool_name=None, tool_args=None, plain_text=""):
    """Creates a mock Ollama response object with optional tool calls."""
    mock_msg = MagicMock()
    mock_msg.content = plain_text
    
    if tool_name and tool_args is not None:
        mock_call = MagicMock()
        mock_call.function.name = tool_name
        mock_call.function.arguments = tool_args
        mock_msg.tool_calls = [mock_call]
    else:
        mock_msg.tool_calls = None
        
    mock_resp = MagicMock()
    mock_resp.message = mock_msg
    return mock_resp

@pytest.fixture
def critic_setup(tmp_path):
    """Provisions a test directory and mock callbacks."""
    test_file = tmp_path / "app.py"
    test_file.write_text("def test():\n    pass\n", encoding="utf-8")
    
    callbacks = {
        "on_progress": MagicMock(),
        "on_warning": MagicMock(),
        "on_error": MagicMock()
    }
    
    return tmp_path, callbacks

# --- 1. Happy Path Agent Tests ---

def test_verify_findings_keeps_genuine_bug(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    # LLM responds immediately with submit_verdict keeping the bug
    mock_client.chat.return_value = make_mock_response(
        tool_name="submit_verdict",
        tool_args={"is_genuine_bug": True, "adjusted_severity": "critical", "reasoning": "Confirmed leak"}
    )
    
    findings = [{"title": "Leak", "file": "app.py", "severity": "high", "line": 2}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    assert len(results) == 1
    assert results[0]["severity"] == "critical"  # Adjusted by the critic
    assert results[0]["reviewer_notes"] == "Confirmed leak"
    
    callbacks["on_progress"].assert_any_call(" - Kept: Confirmed leak")

def test_verify_findings_rejects_false_positive(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    # LLM responds immediately rejecting the bug
    mock_client.chat.return_value = make_mock_response(
        tool_name="submit_verdict",
        tool_args={"is_genuine_bug": False, "reasoning": "Hallucinated import"}
    )
    
    findings = [{"title": "Bad Import", "file": "app.py", "severity": "low", "line": 1}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    # The finding should be dropped entirely
    assert len(results) == 0
    callbacks["on_progress"].assert_any_call(" - Rejected: Hallucinated import")

# --- 2. Multi-Turn / Tool Interaction Tests ---

def test_verify_findings_nudges_llm_without_tools(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    # Turn 1: LLM just talks, no tools
    resp1 = make_mock_response(plain_text="Let me look at this...")
    # Turn 2: LLM submits the verdict
    resp2 = make_mock_response(
        tool_name="submit_verdict",
        tool_args={"is_genuine_bug": True, "adjusted_severity": "low", "reasoning": "Valid but minor"}
    )
    mock_client.chat.side_effect = [resp1, resp2]
    
    findings = [{"title": "Minor issue", "file": "app.py", "severity": "medium", "line": 1}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    assert len(results) == 1
    assert mock_client.chat.call_count == 2
    
    # Verify the nudge message was injected in the second call
    second_call_args = mock_client.chat.call_args_list[1][1]["messages"]
    assert "Please explore the codebase" in second_call_args[3]["content"]

# --- 3. Edge Cases & Resilience Tests ---

def test_verify_findings_handles_missing_files(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    findings = [{"title": "Ghost Bug", "file": "missing.py", "severity": "high", "line": 1}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    # If the file doesn't exist, it keeps the finding by default and doesn't bother the LLM
    assert len(results) == 1
    mock_client.chat.assert_not_called()

def test_verify_findings_blocks_path_traversal(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    findings = [{"title": "Sneaky", "file": "../outside.py", "severity": "high", "line": 1}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    # Prompt injection escapes are dropped immediately
    assert len(results) == 0
    callbacks["on_warning"].assert_called_once()
    assert "out-of-repo path" in callbacks["on_warning"].call_args[0][0]
    mock_client.chat.assert_not_called()

def test_verify_findings_handles_llm_crash(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    # Simulate a network crash or context overflow
    mock_client.chat.side_effect = Exception("Connection Timeout")
    
    findings = [{"title": "Crash Test", "file": "app.py", "severity": "high", "line": 1}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    # Keeps the finding by default if verification fails mechanically
    assert len(results) == 1
    callbacks["on_warning"].assert_called_once()
    assert "Critic call failed" in callbacks["on_warning"].call_args[0][0]

def test_verify_findings_turn_limit_exhausted(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    
    # LLM refuses to call tools 10 times in a row
    mock_client.chat.return_value = make_mock_response(plain_text="Thinking...")
    
    findings = [{"title": "Endless Loop", "file": "app.py", "severity": "high", "line": 1}]
    
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)
    
    # Exhausts 10 turns, keeps the finding, warns the user
    assert mock_client.chat.call_count == 10
    assert len(results) == 1
    callbacks["on_warning"].assert_called_once()
    assert "Hit turn limit" in callbacks["on_warning"].call_args[0][0]

# --- Verdict parsing / options ---

def test_verify_findings_treats_string_false_as_rejection(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(
        tool_name="submit_verdict",
        tool_args={"is_genuine_bug": "false", "adjusted_severity": "low", "reasoning": "Not real"}
    )

    findings = [{"title": "Bogus", "file": "app.py", "severity": "high", "line": 1}]

    assert verify_findings(mock_client, "model", tmp_path, findings, **callbacks) == []

def test_verify_findings_ignores_invalid_adjusted_severity(critic_setup):
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(
        tool_name="submit_verdict",
        tool_args={"is_genuine_bug": True, "adjusted_severity": "super-bad", "reasoning": "Real"}
    )

    findings = [{"title": "Leak", "file": "app.py", "severity": "high", "line": 1}]
    results = verify_findings(mock_client, "model", tmp_path, findings, **callbacks)

    assert results[0]["severity"] == "high"

def test_verify_findings_sets_context_window(critic_setup):
    from auditor.utils.llm import MAX_CONTEXT, OUTPUT_RESERVE
    tmp_path, callbacks = critic_setup
    mock_client = MagicMock()
    mock_client.chat.return_value = make_mock_response(
        tool_name="submit_verdict",
        tool_args={"is_genuine_bug": True, "adjusted_severity": "low", "reasoning": "Real"}
    )

    verify_findings(mock_client, "model", tmp_path, [{"title": "x", "file": "app.py", "line": 1}], **callbacks)

    options = mock_client.chat.call_args.kwargs["options"]
    assert options["num_ctx"] == MAX_CONTEXT
    assert options["num_predict"] == OUTPUT_RESERVE
