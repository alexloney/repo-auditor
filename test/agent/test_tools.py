import json
import pytest
from unittest.mock import patch

from auditor.agent.coverage import ReadCoverage
from auditor.agent.tools import (
    _resolve_within_root,
    make_list_files_tool,
    make_read_file_tool,
    make_read_file_range_tool,
    make_search_code_tool,
    make_report_issue_tool,
    make_submit_verdict_tool,
)

# --- 1. Fixtures ---

@pytest.fixture
def workspace(tmp_path):
    """A resolved temporary repo root. Tools take the root explicitly, so no chdir is needed."""
    return tmp_path.resolve()

# --- 2. Path Resolution Tests ---

def test_resolve_within_root(workspace):
    # Valid internal paths
    assert _resolve_within_root(workspace, ".") == workspace
    assert _resolve_within_root(workspace, "src/main.py") == workspace / "src" / "main.py"
    assert _resolve_within_root(workspace, r"src\main.py") == workspace / "src" / "main.py"

    # Path traversal attempts (prompt injection)
    with pytest.raises(ValueError, match="escapes the repository root"):
        _resolve_within_root(workspace, "../outside.txt")

    # Absolute path attempts outside the workspace
    parent_dir = workspace.parent / "sneaky.txt"
    with pytest.raises(ValueError, match="escapes the repository root"):
        _resolve_within_root(workspace, str(parent_dir))

def test_tools_ignore_current_directory(workspace, tmp_path_factory, monkeypatch):
    """Tools must resolve against their bound root, never the process cwd."""
    (workspace / "app.py").write_text("x = 1", encoding="utf-8")
    monkeypatch.chdir(tmp_path_factory.mktemp("elsewhere"))

    assert "x = 1" in make_read_file_tool(workspace)("app.py")

# --- 3. Directory and File Reading Tests ---

def test_list_files(workspace):
    (workspace / "file1.txt").touch()
    (workspace / "dir1").mkdir()

    list_files = make_list_files_tool(workspace, extensions=None, skip_dirs=None)

    result = list_files(".")
    data = json.loads(result)

    assert data["directory"] == "."
    assert "file1.txt" in data["contents"]
    assert "dir1/" in data["contents"]

def test_list_files_invalid(workspace):
    list_files = make_list_files_tool(workspace, extensions=None, skip_dirs=None)

    result = list_files("missing_dir")
    assert "Error reading directory" in result

@patch("auditor.agent.tools.estimate_tokens", return_value=100)
def test_read_file_success(mock_tokens, workspace):
    target = workspace / "app.py"
    target.write_text("print('hello')", encoding="utf-8")

    assert make_read_file_tool(workspace)("app.py") == "   1 | print('hello')"

@patch("auditor.agent.tools.estimate_tokens", return_value=99999)
def test_read_file_too_large(mock_tokens, workspace):
    target = workspace / "app.py"
    target.write_text("print('hello')", encoding="utf-8")
    coverage = ReadCoverage()

    result = make_read_file_tool(workspace, coverage)("app.py")
    assert "File too large to read entirely" in result
    assert len(coverage) == 0  # nothing was actually read

def test_read_file_rejects_escape(workspace):
    assert "escapes the repository root" in make_read_file_tool(workspace)("../outside.py")

# --- 4. Line Range Tests ---

@patch("auditor.agent.tools.estimate_tokens", return_value=50)
def test_read_file_range_success(mock_tokens, workspace):
    target = workspace / "app.py"
    target.write_text("line1\nline2\nline3\nline4\nline5", encoding="utf-8")

    result = make_read_file_range_tool(workspace)("app.py", 2, 4)
    # Checks that it grabbed lines 2 through 4 and prefixed them correctly
    assert "   2 | line2" in result
    assert "   4 | line4" in result
    assert "line1" not in result
    assert "line5" not in result

def test_read_file_range_out_of_bounds(workspace):
    target = workspace / "app.py"
    target.write_text("line1\nline2", encoding="utf-8")

    result = make_read_file_range_tool(workspace)("app.py", 5, 10)
    assert "only has 2 lines" in result

# --- 5. Coverage Tracking Tests ---

def test_read_tools_record_coverage(workspace):
    (workspace / "src").mkdir()
    (workspace / "src" / "a.py").write_text("a = 1\n", encoding="utf-8")
    (workspace / "src" / "b.py").write_text("\n".join(f"line{i}" for i in range(1, 301)), encoding="utf-8")
    coverage = ReadCoverage()

    make_read_file_tool(workspace, coverage)("src/a.py")
    read_range = make_read_file_range_tool(workspace, coverage)
    read_range(r"src\b.py", 1, 50)
    read_range("src/b.py", 40, 80)
    read_range("src/b.py", 200, 250)

    assert coverage.summary() == "- src/a.py (full)\n- src/b.py (lines 1-80, 200-250)"

def test_coverage_full_read_supersedes_ranges():
    coverage = ReadCoverage()
    coverage.record_range("a.py", 1, 10)
    coverage.record_full("a.py")
    coverage.record_range("a.py", 20, 30)

    assert coverage.summary() == "- a.py (full)"

# --- 6. Code Search Tests ---

def test_search_code_success(workspace):
    (workspace / "app.py").write_text("def hello():\n    return True\n", encoding="utf-8")
    (workspace / "test.py").write_text("def test_hello():\n    pass\n", encoding="utf-8")

    search_code = make_search_code_tool(workspace, extensions=None, skip_dirs=None)

    result = search_code("def hello")
    assert "app.py:1: def hello():" in result
    assert "test.py" not in result  # Doesn't match exactly

def test_search_code_no_matches(workspace):
    (workspace / "app.py").write_text("def hello():\n    return True\n", encoding="utf-8")
    search_code = make_search_code_tool(workspace, extensions=None, skip_dirs=None)

    assert "No matches found" in search_code("missing_function")

def test_search_code_reports_posix_paths(workspace):
    (workspace / "src").mkdir()
    (workspace / "src" / "app.py").write_text("needle\n", encoding="utf-8")

    assert make_search_code_tool(workspace, None, None)("needle") == "src/app.py:1: needle"

@patch("auditor.agent.tools.MAX_SEARCH_RESULTS", 2)
def test_search_code_truncation(workspace):
    # Write 3 matches to force truncation
    (workspace / "app.py").write_text("match\nmatch\nmatch\n", encoding="utf-8")

    search_code = make_search_code_tool(workspace, extensions=None, skip_dirs=None)

    result = search_code("match")
    lines = result.splitlines()

    # 2 match lines + 1 truncation warning line = 3 lines total
    assert len(lines) == 3
    assert "results truncated at 2 matches" in lines[-1]

# --- 7. Ledger / Evaluation Tests ---

def test_report_issue(workspace):
    (workspace / "app.py").write_text("import db\n\ndb.execute('SELECT * FROM t WHERE id=' + uid)\n", encoding="utf-8")
    recorded = []
    report_issue = make_report_issue_tool(workspace, recorded.append)

    result = report_issue(
        filepath="app.py",
        line=3,
        title="SQLi",
        description="Found vulnerability",
        evidence="db.execute('SELECT * FROM t WHERE id=' + uid)",
        severity="high",
        category="security",
        suggested_solution="Use prepared statements"
    )

    assert result == "Issue successfully logged to the ledger."
    assert recorded[0]["title"] == "SQLi"
    assert recorded[0]["file"] == "app.py"
    assert recorded[0]["line"] == 3

def test_report_issue_corrects_line_from_evidence(workspace):
    (workspace / "app.py").write_text("a = 1\nb = 2\nc = a / 0\n", encoding="utf-8")
    recorded = []
    report_issue = make_report_issue_tool(workspace, recorded.append)

    report_issue(filepath="app.py", line="9", title="t", description="d", evidence="  3 | c = a / 0")

    assert recorded[0]["line"] == 3  # gutter stripped, wrong (string) line replaced

def test_report_issue_rejects_evidence_not_in_file(workspace):
    (workspace / "app.py").write_text("a = 1\n", encoding="utf-8")
    recorded = []
    report_issue = make_report_issue_tool(workspace, recorded.append)

    result = report_issue(filepath="app.py", line=1, title="t", description="d", evidence="eval(user_input)")

    assert "evidence was not found" in result
    assert recorded == []

def test_report_issue_normalizes_path(workspace):
    (workspace / "src").mkdir()
    (workspace / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
    recorded = []
    report_issue = make_report_issue_tool(workspace, recorded.append)

    report_issue(filepath=r"./src\app.py", line=1, title="t", description="d", evidence="x = 1")

    assert recorded[0]["file"] == "src/app.py"

def test_report_issue_rejects_path_outside_repo(workspace):
    recorded = []
    report_issue = make_report_issue_tool(workspace, recorded.append)

    result = report_issue(filepath="../outside.py", line=1, title="t", description="d", evidence="x")

    assert result.startswith("Error logging issue")
    assert recorded == []

def test_submit_verdict_forwards_arguments():
    received = []
    submit_verdict = make_submit_verdict_tool(received.append)

    assert submit_verdict(True, "Looks real", "high") == "Verdict received."
    assert received == [{"is_genuine_bug": True, "reasoning": "Looks real", "adjusted_severity": "high"}]

def test_tool_parameter_descriptions_reach_schema(workspace):
    from ollama._utils import convert_function_to_tool
    tools = [make_read_file_tool(workspace), make_read_file_range_tool(workspace),
             make_list_files_tool(workspace, None, None), make_search_code_tool(workspace, None, None),
             make_report_issue_tool(workspace, lambda _: None),
             make_submit_verdict_tool(lambda _: None)]

    for tool in tools:
        props = convert_function_to_tool(tool).function.parameters.properties
        for name, prop in props.items():
            assert prop.description, f"{tool.__name__}.{name} has no description"
