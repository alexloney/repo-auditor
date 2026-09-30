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
@patch("auditor.scanners.single_file.append_finding")
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
    mock_list_files.assert_called_once_with(mock_scanner.target_dir, mock_scanner.skip_dirs, mock_scanner.extensions)
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
@patch("auditor.scanners.single_file.append_finding")
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
@patch("auditor.scanners.single_file.append_finding")
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