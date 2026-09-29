import pytest
from unittest.mock import patch, MagicMock
from auditor.pipeline import get_available_scanners

def test_get_available_scanners():
    scanners = get_available_scanners()
    assert isinstance(scanners, dict)
    for scanner_id, scanner_cls in scanners.items():
        assert hasattr(scanner_cls, "id")
        assert hasattr(scanner_cls, "name")
        assert hasattr(scanner_cls, "auto_enabled")
        assert callable(getattr(scanner_cls, "run", None))
