from unittest.mock import MagicMock

from auditor.evaluator.grounding import ground_findings

def make_repo(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\ny = x / 0\nprint(y)\n", encoding="utf-8")
    return tmp_path

def test_ground_findings_keeps_and_corrects_line(tmp_path):
    findings = [{"title": "Div by zero", "file": "app.py", "line": 7, "evidence": "y = x / 0"}]

    kept, dropped, corrected = ground_findings(make_repo(tmp_path), findings)

    assert (len(kept), dropped, corrected) == (1, 0, 1)
    assert kept[0]["line"] == 2

def test_ground_findings_fills_missing_line(tmp_path):
    findings = [{"title": "Div by zero", "file": "app.py", "evidence": "y = x / 0"}]

    kept, _, corrected = ground_findings(make_repo(tmp_path), findings)

    assert kept[0]["line"] == 2
    assert corrected == 1

def test_ground_findings_drops_hallucinated_evidence(tmp_path):
    on_warning = MagicMock()
    findings = [{"title": "Fake", "file": "app.py", "line": 1, "evidence": "os.system(cmd)"}]

    kept, dropped, _ = ground_findings(make_repo(tmp_path), findings, on_warning)

    assert kept == [] and dropped == 1
    assert "evidence not found" in on_warning.call_args[0][0]

def test_ground_findings_keeps_unverifiable_findings(tmp_path):
    findings = [
        {"title": "Old ledger entry", "file": "app.py", "line": "3"},           # no evidence
        {"title": "Missing file", "file": "gone.py", "line": 1, "evidence": "x"},
        {"title": "Outside repo", "file": "../x.py", "line": 1, "evidence": "x"},
    ]

    kept, dropped, _ = ground_findings(make_repo(tmp_path), findings)

    assert len(kept) == 3 and dropped == 0
    assert kept[0]["line"] == 3  # string line still coerced
