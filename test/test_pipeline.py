import pytest
from unittest.mock import patch, MagicMock
from auditor.pipeline import get_available_scanners, filter_scanners

def test_get_available_scanners():
    scanners = get_available_scanners()
    assert isinstance(scanners, dict)
    for scanner_id, scanner_cls in scanners.items():
        assert hasattr(scanner_cls, "id")
        assert hasattr(scanner_cls, "name")
        assert hasattr(scanner_cls, "auto_enabled")
        assert callable(getattr(scanner_cls, "run", None))

def get_mock_registry():
    """Helper to generate a fake dictionary of available scanners."""
    mock_shallow = MagicMock()
    mock_shallow.auto_enabled = True
    
    mock_deep = MagicMock()
    mock_deep.auto_enabled = True
    
    mock_taint = MagicMock()
    mock_taint.auto_enabled = False  # Simulates a module starting with '_'
    
    return {
        "shallow": mock_shallow,
        "deep": mock_deep,
        "_taint": mock_taint
    }

def test_filter_scanners_all():
    registry = get_mock_registry()
    
    results, skipped = filter_scanners("all", registry)
    
    assert len(results) == 2
    assert registry["shallow"] in results
    assert registry["deep"] in results
    assert registry["_taint"] not in results
    
    # Assert against the skipped IDs list
    assert "_taint" in skipped

def test_filter_scanners_explicit_list():
    registry = get_mock_registry()
    
    results, skipped = filter_scanners(" Shallow , _TAINT ", registry)
    
    assert len(results) == 2
    assert registry["shallow"] in results
    assert registry["_taint"] in results
    assert registry["deep"] not in results
    
    # Explicit requests bypass the auto_enabled check, so nothing is skipped
    assert len(skipped) == 0

def test_filter_scanners_ignores_missing_ids():
    registry = get_mock_registry()
    
    results, skipped = filter_scanners("shallow, typo_scanner", registry)
    
    assert len(results) == 1
    assert registry["shallow"] in results
    assert len(skipped) == 0

def test_get_available_scanners_registers_classes_from_defining_module():
    """owasp.py imports SingleFileScanner to subclass it; it must not re-register it."""
    registry = get_available_scanners()

    assert registry["single-file"].__module__ == "auditor.scanners.single_file"
    assert registry["owasp"].__module__ == "auditor.scanners.owasp"
    assert registry["single-file"].auto_enabled is True

@patch("auditor.pipeline.ollama.Client")
def test_execute_audit_sets_client_timeout(mock_client_cls, tmp_path):
    from auditor.pipeline import execute_audit
    execute_audit(tmp_path, [], "m", "http://h:1", str(tmp_path / "none.json"), str(tmp_path / "r.md"),
                  request_timeout=123)
    mock_client_cls.assert_called_once_with(host="http://h:1", timeout=123)

@patch("auditor.pipeline.verify_findings", side_effect=lambda client, model, target, findings, *a, **k: findings)
@patch("auditor.pipeline.ollama.Client")
def test_execute_audit_drops_findings_with_hallucinated_evidence(mock_client_cls, mock_verify, tmp_path):
    import json
    from auditor.pipeline import execute_audit
    (tmp_path / "app.py").write_text("x = 1", encoding="utf-8")
    ledger = tmp_path / "ledger.json"
    ledger.write_text(
        json.dumps({"title": "Real", "file": "app.py", "evidence": "x = 1"}) + "\n"
        + json.dumps({"title": "Fake", "file": "app.py", "evidence": "eval(x)"}) + "\n",
        encoding="utf-8",
    )

    execute_audit(tmp_path, [], "m", "h", str(ledger), str(tmp_path / "r.md"))

    verified = mock_verify.call_args[0][3]
    assert [f["title"] for f in verified] == ["Real"]
    assert verified[0]["line"] == 1

@patch("auditor.pipeline.ollama.Client")
def test_execute_audit_passes_scanner_options(mock_client_cls, tmp_path):
    from auditor.pipeline import execute_audit
    seen = {}

    class FakeScanner:
        name = "Fake"
        def __init__(self, **kwargs):
            seen.update(kwargs)
        def run(self):
            pass

    execute_audit(tmp_path, [FakeScanner], "m", "h", str(tmp_path / "none.json"), str(tmp_path / "r.md"),
                  scanner_options={"batch_max_files": 3})
    assert seen["options"] == {"batch_max_files": 3}
