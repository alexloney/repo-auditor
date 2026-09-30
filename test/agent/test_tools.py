import json
import pytest
from pathlib import Path
from unittest.mock import patch

from auditor.agent.tools import (
    _resolve_within_root,
    list_files,
    read_file,
    read_file_range,
    search_code,
    make_report_issue_tool,
    submit_verdict
)

# --- 1. Fixtures ---

@pytest.fixture
def workspace(monkeypatch, tmp_path):
    """Safely changes the working directory to a temporary folder for the agent tools."""
    monkeypatch.chdir(tmp_path)
    return tmp_path

# --- 2. Path Resolution Tests ---

def test_resolve_within_root(workspace):
    # Valid internal paths
    assert _resolve_within_root(".") == workspace
    assert _resolve_within_root("src/main.py") == workspace / "src" / "main.py"

    # Path traversal attempts (prompt injection)
    with pytest.raises(ValueError, match="escapes the repository root"):
        _resolve_within_root("../outside.txt")

    # Absolute path attempts outside the workspace
    parent_dir = workspace.parent / "sneaky.txt"
    with pytest.raises(ValueError, match="escapes the repository root"):
        _resolve_within_root(str(parent_dir))

# --- 3. Directory and File Reading Tests ---

def test_list_files(workspace):
    (workspace / "file1.txt").touch()
    (workspace / "dir1").mkdir()
    
    result = list_files(".")
    data = json.loads(result)
    
    assert data["directory"] == "."
    assert "file1.txt" in data["contents"]
    assert "dir1" in data["contents"]

def test_list_files_invalid(workspace):
    result = list_files("missing_dir")
    assert "Error reading directory" in result

@patch("auditor.agent.tools.estimate_tokens", return_value=100)
def test_read_file_success(mock_tokens, workspace):
    target = workspace / "app.py"
    target.write_text("print('hello')", encoding="utf-8")
    
    assert read_file("app.py") == "print('hello')"

@patch("auditor.agent.tools.estimate_tokens", return_value=99999)
def test_read_file_too_large(mock_tokens, workspace):
    target = workspace / "app.py"
    target.write_text("print('hello')", encoding="utf-8")
    
    result = read_file("app.py")
    assert "File too large to read entirely" in result

# --- 4. Line Range Tests ---

@patch("auditor.agent.tools.estimate_tokens", return_value=50)
def test_read_file_range_success(mock_tokens, workspace):
    target = workspace / "app.py"
    target.write_text("line1\nline2\nline3\nline4\nline5", encoding="utf-8")
    
    result = read_file_range("app.py", 2, 4)
    # Checks that it grabbed lines 2 through 4 and prefixed them correctly
    assert "   2 | line2" in result
    assert "   4 | line4" in result
    assert "line1" not in result
    assert "line5" not in result

def test_read_file_range_out_of_bounds(workspace):
    target = workspace / "app.py"
    target.write_text("line1\nline2", encoding="utf-8")
    
    result = read_file_range("app.py", 5, 10)
    assert "only has 2 lines" in result

# --- 5. Code Search Tests ---

def test_search_code_success(workspace):
    (workspace / "app.py").write_text("def hello():\n    return True\n", encoding="utf-8")
    (workspace / "test.py").write_text("def test_hello():\n    pass\n", encoding="utf-8")
    
    result = search_code("def hello")
    assert "app.py:1: def hello():" in result
    assert "test.py" not in result  # Doesn't match exactly

def test_search_code_no_matches(workspace):
    (workspace / "app.py").write_text("def hello():\n    return True\n", encoding="utf-8")
    assert "No matches found" in search_code("missing_function")

@patch("auditor.agent.tools.MAX_SEARCH_RESULTS", 2)
def test_search_code_truncation(workspace):
    # Write 3 matches to force truncation
    (workspace / "app.py").write_text("match\nmatch\nmatch\n", encoding="utf-8")
    
    result = search_code("match")
    lines = result.splitlines()
    
    # 2 match lines + 1 truncation warning line = 3 lines total
    assert len(lines) == 3
    assert "results truncated at 2 matches" in lines[-1]

# --- 6. Ledger / Evaluation Tests ---

def test_report_issue(workspace):
    ledger_path = workspace / "test_ledger.json"
    
    # 1. Initialize the tool using the factory
    report_issue = make_report_issue_tool(ledger_path)
    
    # 2. Call the newly created function
    result = report_issue(
        filepath="app.py",
        line=10,
        title="SQLi",
        description="Found vulnerability",
        severity="high",
        category="security",
        suggested_solution="Use prepared statements"
    )
    
    assert result == "Issue successfully logged to the ledger."
    
    data = json.loads(ledger_path.read_text(encoding="utf-8"))
    assert data["title"] == "SQLi"
    assert data["file"] == "app.py"

def test_submit_verdict():
    # Simple static string return
    assert submit_verdict(True, "Looks real", "high") == "Verdict received."