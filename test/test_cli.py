import pytest
from unittest.mock import patch, MagicMock
from auditor.cli import main, parse_args, list_scanners

def test_parse_args_list():
    args = parse_args(["--list"])
    assert args.list is True

def test_parse_args_with_target():
    args = parse_args(["/fake/repo"])
    assert args.repo_path == "/fake/repo"
    assert args.scans == "all"

def test_parse_args_with_scans():
    args = parse_args(["/fake/repo", "--scans", "scan1,scan2"])
    assert args.repo_path == "/fake/repo"
    assert args.scans == "scan1,scan2"

def test_parse_args_with_list_flag():
    args = parse_args(["/fake/repo", "--list"])
    assert args.repo_path == "/fake/repo"
    assert args.list is True

def test_parse_args_without_repo_path():
    with pytest.raises(SystemExit) as excinfo:
        parse_args([])
    assert excinfo.value.code == 1

def test_parse_args_with_model():
    args = parse_args(["/fake/repo", "--model", "custom-model"])
    assert args.repo_path == "/fake/repo"
    assert args.model == "custom-model"

def test_parse_args_with_default_model():
    args = parse_args(["/fake/repo"])
    assert args.repo_path == "/fake/repo"
    assert args.model == "qwen-coder-64k:latest"

def test_parse_args_with_ollama():
    args = parse_args(["/fake/repo", "--ollama", "custom-ollama-host:port"])
    assert args.repo_path == "/fake/repo"
    assert args.ollama == "custom-ollama-host:port"

def test_parse_args_with_default_ollama():
    args = parse_args(["/fake/repo"])
    assert args.repo_path == "/fake/repo"
    assert args.ollama == "http://localhost:11434"

def test_parse_args_with_ledger():
    args = parse_args(["/fake/repo", "--ledger", "custom-ledger"])
    assert args.repo_path == "/fake/repo"
    assert args.ledger == "custom-ledger"

def test_parse_args_with_default_ledger():
    args = parse_args(["/fake/repo"])
    assert args.repo_path == "/fake/repo"
    assert args.ledger == "findings.json"

def test_parse_args_with_report():
    args = parse_args(["/fake/repo", "--report", "custom-report"])
    assert args.repo_path == "/fake/repo"
    assert args.report == "custom-report"

def test_parse_args_with_default_report():
    args = parse_args(["/fake/repo"])
    assert args.repo_path == "/fake/repo"
    assert args.report == "report.md"


# This will allow us to replace the "get_available_scanners()"
# funciton with a mocked return value, so we don't need to
# actually have the test scan the physical filesystem.
@patch("auditor.cli.get_available_scanners")
def test_list_scanners(mock_get_scanners, capsys):
    # Create two mock return values for scan results and
    # set them as our mocked return value.
    mock_enabled = MagicMock()
    mock_enabled.name = "Shallow Syntax Scan"
    mock_enabled.auto_enabled = True
    mock_disabled = MagicMock()
    mock_disabled.name = "Deep Taint Scan"
    mock_disabled.auto_enabled = False
    mock_get_scanners.return_value = {
        "shallow": mock_enabled,
        "_taint": mock_disabled
    }

    # Now we execute our scanner list and capture the
    # STDOUT/STDERR output.
    exit_code = list_scanners()
    captured = capsys.readouterr()
    output = captured.out

    # And verify that the expected output was captured
    assert exit_code == 0
    assert "Available scan plugins:" in output
    assert "shallow" in output
    assert "Shallow Syntax Scan" in output
    assert "_taint" in output
    assert "(disabled: module name starts with '_')" in output

def test_main_rejects_missing_target(tmp_path, capsys):
    assert main([str(tmp_path / "does-not-exist")]) == 1
    assert "does not exist" in capsys.readouterr().out

@patch("auditor.cli.execute_audit")
@patch("auditor.cli.get_available_scanners")
def test_main_rejects_unknown_scanner(mock_get_scanners, mock_execute, tmp_path, capsys):
    mock_get_scanners.return_value = {"single-file": MagicMock(auto_enabled=True)}

    assert main([str(tmp_path), "--scans", "single-file,typo"]) == 1
    assert "Unknown scanner(s): typo" in capsys.readouterr().out
    mock_execute.assert_not_called()

def test_parse_args_max_turns():
    from auditor.agent.agent import DEFAULT_MAX_TURNS
    assert parse_args(["/fake/repo"]).max_turns == DEFAULT_MAX_TURNS
    assert parse_args(["/fake/repo", "--max-turns", "250"]).max_turns == 250

@patch("auditor.cli.execute_audit", return_value=0)
def test_main_passes_max_turns(mock_execute, tmp_path):
    main([str(tmp_path), "--scans", "arch", "--max-turns", "7"])
    assert mock_execute.call_args.kwargs["max_turns"] == 7

def test_add_extensions_appends_to_defaults_and_normalizes():
    from auditor.cli import DEFAULT_EXTENSION
    args = parse_args(["/fake/repo", "--add-extensions", "yml, .TOML,,py"])

    assert args.extensions[:len(DEFAULT_EXTENSION)] == DEFAULT_EXTENSION
    assert args.extensions[-2:] == [".yml", ".toml"]
    assert args.extensions.count(".py") == 1  # already a default, not duplicated

def test_add_extensions_appends_to_replaced_list():
    args = parse_args(["/fake/repo", "--extensions", "PY", "--add-extensions", "go"])
    assert args.extensions == [".py", ".go"]

def test_empty_extensions_means_all_even_with_additions():
    args = parse_args(["/fake/repo", "--extensions", "", "--add-extensions", "go"])
    assert args.extensions is None

def test_add_skip_dirs_appends_to_defaults():
    from auditor.cli import DEFAULT_SKIP_DIRS
    args = parse_args(["/fake/repo", "--add-skip-dirs", "fixtures, docs"])

    assert set(DEFAULT_SKIP_DIRS) <= set(args.skip_dirs)
    assert args.skip_dirs[-2:] == ["fixtures", "docs"]

def test_add_skip_dirs_appends_to_replaced_list():
    args = parse_args(["/fake/repo", "--skip-dirs", "a,b", "--add-skip-dirs", "c,a"])
    assert args.skip_dirs == ["a", "b", "c"]

@patch("auditor.cli.execute_audit", return_value=0)
def test_main_passes_timeout(mock_execute, tmp_path):
    from auditor.pipeline import DEFAULT_REQUEST_TIMEOUT
    main([str(tmp_path), "--scans", "arch"])
    assert mock_execute.call_args.kwargs["request_timeout"] == DEFAULT_REQUEST_TIMEOUT

    main([str(tmp_path), "--scans", "arch", "--timeout", "90"])
    assert mock_execute.call_args.kwargs["request_timeout"] == 90
