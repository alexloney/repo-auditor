import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from auditor.scanners.single_file import SingleFileScanner

@pytest.fixture
def mock_scanner(tmp_path):
    """Fixture to set up a SingleFileScanner with mocked dependencies and callbacks."""
    client = MagicMock()
    ledger_path = tmp_path / "ledger.json"
    
    # Instantiate the scanner
    scanner = SingleFileScanner(
        client=client,
        model="test-model",
        target_dir=tmp_path,
        ledger_path=ledger_path,
    )
    
    # Inject variables that would normally be set by the orchestrator/BaseScanner
    scanner.model = "test-model"
    scanner.skip_dirs = set()
    scanner.extensions = {".py"}
    
    # Attach mocked callbacks to verify terminal output behavior
    scanner.on_progress = MagicMock()
    scanner.on_warning = MagicMock()
    scanner.on_error = MagicMock()
    
    return scanner

@patch("auditor.scanners.single_file.list_auditable_files")
@patch("auditor.scanners.single_file.call_json")
@patch("auditor.scanners.base.append_finding")
def test_single_file_scanner_success(mock_append, mock_call_json, mock_list_files, mock_scanner, tmp_path):
    # 1. Setup Filesystem Mock
    # Create a physical file in the temporary directory so read_text() works natively
    test_file = "app.py"
    (tmp_path / test_file).write_text("print('hello')", encoding="utf-8")
    mock_list_files.return_value = [test_file]
    
    # 2. Setup LLM Mock
    mock_call_json.return_value = {
        "findings": [
            {"title": "Test Bug", "severity": "high", "description": "A bad bug."}
        ]
    }
    
    # 3. Execution
    mock_scanner.run()
    
    # 4. Assertions
    mock_list_files.assert_called_once_with(mock_scanner.target_dir, mock_scanner.extensions, mock_scanner.skip_dirs)
    mock_call_json.assert_called_once()
    
    # Verify the finding was appended and the file path was injected correctly
    mock_append.assert_called_once()
    appended_data = mock_append.call_args[0][1]
    assert appended_data["title"] == "Test Bug"
    assert appended_data["file"] == "app.py"
    
    # Verify UI callbacks
    assert mock_scanner.on_progress.call_count == 3
    mock_scanner.on_error.assert_not_called()
    mock_scanner.on_warning.assert_not_called()

@patch("auditor.scanners.single_file.list_auditable_files")
def test_single_file_scanner_file_read_error(mock_list_files, mock_scanner):
    # Return a file that doesn't actually exist in tmp_path
    mock_list_files.return_value = ["missing.py"]
    
    # Execution
    mock_scanner.run()
    
    # Assertions: It should catch the OSError and trigger on_error, without crashing
    mock_scanner.on_error.assert_called_once()
    assert "could not read file" in mock_scanner.on_error.call_args[0][0]
    mock_scanner.on_warning.assert_not_called()

@patch("auditor.scanners.single_file.list_auditable_files")
@patch("auditor.scanners.single_file.call_json")
@patch("auditor.scanners.base.append_finding")
def test_single_file_scanner_llm_failure(mock_append, mock_call_json, mock_list_files, mock_scanner, tmp_path):
    # Setup a valid file
    test_file = "app.py"
    (tmp_path / test_file).write_text("print('hello')", encoding="utf-8")
    mock_list_files.return_value = [test_file]
    
    # Force the LLM to throw an exception
    mock_call_json.side_effect = Exception("API Timeout")
    
    # Execution
    mock_scanner.run()
    
    # Assertions: It should catch the Exception, trigger on_warning, and skip the append step
    mock_scanner.on_warning.assert_called_once()
    assert "review failed -> API Timeout" in mock_scanner.on_warning.call_args[0][0]
    
    mock_append.assert_not_called()

@patch("auditor.scanners.single_file.list_auditable_files")
@patch("auditor.scanners.single_file.call_json")
@patch("auditor.scanners.base.append_finding")
def test_single_file_scanner_no_findings(mock_append, mock_call_json, mock_list_files, mock_scanner, tmp_path):
    # Setup a valid file
    test_file = "app.py"
    (tmp_path / test_file).write_text("print('hello')", encoding="utf-8")
    mock_list_files.return_value = [test_file]
    
    # Simulate a clean file with no bugs
    mock_call_json.return_value = {"findings": []}
    
    # Execution
    mock_scanner.run()
    
    # Assertions
    mock_append.assert_not_called()

@patch("auditor.scanners.single_file.list_auditable_files")
@patch("auditor.scanners.single_file.call_json")
@patch("auditor.scanners.base.append_finding")
def test_owasp_scanner_uses_its_own_prompt_and_schema(mock_append, mock_call_json, mock_list_files, tmp_path):
    from auditor.scanners.owasp import OwaspScanner, OWASP_SYSTEM_PROMPT

    (tmp_path / "app.py").write_text("print('hello')", encoding="utf-8")
    mock_list_files.return_value = ["app.py"]
    mock_call_json.return_value = {"findings": []}

    OwaspScanner(client=MagicMock(), model="m", target_dir=tmp_path, ledger_path=tmp_path / "l.json").run()

    _, _, system, user, schema = mock_call_json.call_args[0]
    assert system == OWASP_SYSTEM_PROMPT
    assert "OWASP Top 10" in user
    item = schema["properties"]["findings"]["items"]
    assert {"owasp_category", "vuln_class"} <= set(item["properties"])
    assert {"owasp_category", "vuln_class", "title"} <= set(item["required"])

def test_single_file_schema_unchanged_by_subclass():
    from auditor.scanners.single_file import SINGLE_FILE_FINDINGS_SCHEMA
    import auditor.scanners.owasp  # noqa: F401  (building its schema must not mutate the base one)

    item = SINGLE_FILE_FINDINGS_SCHEMA["properties"]["findings"]["items"]
    assert "owasp_category" not in item["properties"]
    assert "owasp_category" not in item["required"]
    assert "category" in item["properties"]

@patch("auditor.scanners.single_file.list_auditable_files")
@patch("auditor.scanners.single_file.call_json")
@patch("auditor.scanners.base.append_finding")
def test_owasp_findings_are_tagged_security(mock_append, mock_call_json, mock_list_files, tmp_path):
    from auditor.scanners.owasp import OwaspScanner

    (tmp_path / "app.py").write_text("q = 'SELECT ' + x", encoding="utf-8")
    mock_list_files.return_value = ["app.py"]
    mock_call_json.return_value = {"findings": [{"title": "SQLi", "owasp_category": "A03:2021-Injection"}]}

    OwaspScanner(client=MagicMock(), model="m", target_dir=tmp_path, ledger_path=tmp_path / "l.json").run()

    finding = mock_append.call_args[0][1]
    assert finding["category"] == "security"
    assert finding["file"] == "app.py"
    schema_item = mock_call_json.call_args[0][4]["properties"]["findings"]["items"]
    assert "category" not in schema_item["properties"]
    assert "category" not in schema_item["required"]

def test_findings_schema_requires_line_and_evidence():
    from auditor.scanners.single_file import SINGLE_FILE_FINDINGS_SCHEMA
    required = SINGLE_FILE_FINDINGS_SCHEMA["properties"]["findings"]["items"]["required"]
    assert "line" in required and "evidence" in required

@patch("auditor.scanners.base.append_finding")
def test_record_finding_stamps_scanner_id(mock_append, mock_scanner):
    mock_scanner.record_finding({"title": "x"})
    assert mock_append.call_args[0][1]["scanner"] == "single-file"
