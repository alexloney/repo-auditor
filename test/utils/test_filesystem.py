import json
from pathlib import Path
from unittest.mock import patch

from auditor.utils.filesystem import (
    number_lines,
    is_auditable,
    list_auditable_files,
    append_finding,
    MAX_FILE_SIZE_BYTES
)

def test_number_lines():
    content = "def hello():\n    print('world')\n"
    result = number_lines(content)
    
    assert "   1 | def hello():" in result
    assert "   2 |     print('world')" in result

def test_is_auditable_valid():
    assert is_auditable("src/main.py", extensions={".py"}) is True
    assert is_auditable("src/utils/math.cpp", extensions={".cpp"}) is True

def test_is_auditable_skipped_directories():
    assert is_auditable(".venv/lib/main.py", extensions={".py"}, skip_dirs={".venv"}) is False
    assert is_auditable("node_modules/package/index.js", extensions={".js"}, skip_dirs={"node_modules"}) is False
    assert is_auditable(".git/config", extensions={".config"}, skip_dirs={".git"}) is False

def test_is_auditable_skipped_files():
    # Tests matching the SKIP_FILES set
    assert is_auditable("src/test_main.py", extensions={".py"}) is False
    assert is_auditable("src/app.min.js", extensions={".js"}) is False

def test_is_auditable_custom_extensions():
    # Should fail default checks
    assert is_auditable("src/style.css", extensions={".py"}) is False
    # Should pass when explicitly allowed
    assert is_auditable("src/style.css", extensions={".css"}) is True

def test_list_auditable_files(tmp_path):
    # Create a valid file
    (tmp_path / "main.py").write_text("print('hello')")
    
    # Create a file in a standard skipped directory
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    (venv_dir / "script.py").write_text("pass")
    
    # Create an explicitly skipped file
    (tmp_path / "test_main.py").write_text("pass")
    
    # Create an oversized file
    large_file = tmp_path / "large.py"
    # Write a file strictly larger than the MAX_FILE_SIZE_BYTES limit
    large_file.write_bytes(b"0" * (MAX_FILE_SIZE_BYTES + 1))
    
    results = list_auditable_files(tmp_path, extensions={".py"}, skip_dirs={".venv"})
    
    # Extract just the filenames to safely assert across OS separators (\ vs /)
    filenames = [Path(p).name for p in results]
    
    assert "main.py" in filenames
    assert "script.py" not in filenames
    assert "test_main.py" not in filenames
    assert "large.py" not in filenames

def test_list_auditable_files_with_custom_args(tmp_path):
    # Create custom skip dir
    custom_skip = tmp_path / "ignore_me"
    custom_skip.mkdir()
    (custom_skip / "script.py").write_text("pass")
    
    # Create valid file with custom extension
    (tmp_path / "style.css").write_text("body {}")
    
    results = list_auditable_files(
        tmp_path,
        extensions={".css"},
        skip_dirs={"ignore_me"}
    )
    filenames = [Path(p).name for p in results]
    
    assert "style.css" in filenames
    assert "script.py" not in filenames

def test_append_finding(tmp_path):
    ledger = tmp_path / "ledger.json"
    finding = {"title": "Buffer Overflow", "severity": "critical"}
    
    # Append the finding
    append_finding(ledger, finding)
    
    # Read it back and verify it's valid JSON
    content = ledger.read_text(encoding="utf-8").strip()
    data = json.loads(content)
    
    assert data["title"] == "Buffer Overflow"
    assert data["severity"] == "critical"
def test_is_auditable_does_not_skip_test_substrings():
    assert is_auditable("src/latest.py", extensions={".py"}) is True
    assert is_auditable("src/contest.c", extensions={".c"}) is True

def test_is_auditable_skips_test_file_patterns():
    assert is_auditable("pkg/foo_test.go", extensions={".go"}) is False
    assert is_auditable("web/app.spec.ts", extensions={".ts"}) is False
    assert is_auditable("web/app.test.js", extensions={".js"}) is False

def test_list_auditable_files_none_extensions_means_all(tmp_path):
    (tmp_path / "main.py").write_text("pass")
    (tmp_path / "style.css").write_text("body {}")

    results = list_auditable_files(tmp_path, extensions=None, skip_dirs=None)

    assert sorted(results) == ["main.py", "style.css"]

def test_list_auditable_files_uses_forward_slashes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("pass")

    assert list_auditable_files(tmp_path, extensions={".py"}) == ["src/main.py"]
