import pytest
from unittest.mock import patch, MagicMock
from auditor.cli import main, parse_args

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