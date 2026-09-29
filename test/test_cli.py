import pytest
from unittest.mock import patch, MagicMock
from auditor.cli import main, parse_args

def test_parse_args_with_target():
    args = parse_args(["/fake/repo"])
    assert args.repo_path == "/fake/repo"
    assert args.scans == "all"