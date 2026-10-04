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
