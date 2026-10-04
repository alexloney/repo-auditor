from auditor.evaluator.dedupe import dedupe_findings

def test_dedupe_findings_groups_nearby_lines():
    findings = [
        {"title": "Bug A", "file": "app.py", "category": "bug", "line": 12, "confidence": "high", "severity": "medium"},
        {"title": "Bug B", "file": "app.py", "category": "bug", "line": 15, "confidence": "high", "severity": "medium"},
    ]
    
    results = dedupe_findings(findings)
    
    # Lines 12 and 15 both floor-divide to `1`, so they share a group. Only one should survive.
    assert len(results) == 1
    assert results[0]["title"] == "Bug A"  # The first one wins if confidence is tied

def test_dedupe_findings_keeps_different_categories_or_files():
    findings = [
        {"title": "Logic", "file": "app.py", "category": "bug", "line": 12, "confidence": "high"},
        {"title": "Leak", "file": "app.py", "category": "resource-leak", "line": 12, "confidence": "high"},
        {"title": "Logic 2", "file": "utils.py", "category": "bug", "line": 12, "confidence": "high"}
    ]
    
    results = dedupe_findings(findings)
    
    # Different categories or different files mean they don't collide
    assert len(results) == 3

def test_dedupe_findings_prefers_higher_confidence():
    findings = [
        {"title": "Low Conf", "file": "app.py", "category": "security", "line": 45, "confidence": "low", "severity": "critical"},
        {"title": "High Conf", "file": "app.py", "category": "security", "line": 48, "confidence": "high", "severity": "medium"},
        {"title": "Med Conf", "file": "app.py", "category": "security", "line": 41, "confidence": "medium", "severity": "high"},
    ]
    
    results = dedupe_findings(findings)
    
    # They all share group 4 (lines 41-49). The "high" confidence one should overwrite the others.
    assert len(results) == 1
    assert results[0]["title"] == "High Conf"
    assert results[0]["severity"] == "medium"

def test_dedupe_findings_handles_missing_lines_and_fields():
    findings = [
        {"title": "No Line A", "file": "app.py", "category": "bug", "line": None, "confidence": "low"},
        {"title": "No Line B", "file": "app.py", "category": "bug", "confidence": "high"},
    ]
    
    results = dedupe_findings(findings)
    
    # Both default to line group 0. High confidence wins.
    assert len(results) == 1
    assert results[0]["title"] == "No Line B"

def test_dedupe_findings_sorts_by_severity():
    findings = [
        {"title": "Low", "file": "a.py", "category": "bug", "line": 1, "severity": "low"},
        {"title": "Critical", "file": "b.py", "category": "bug", "line": 1, "severity": "critical"},
        {"title": "High", "file": "c.py", "category": "bug", "line": 1, "severity": "high"},
        {"title": "Medium", "file": "d.py", "category": "bug", "line": 1, "severity": "medium"},
    ]
    
    results = dedupe_findings(findings)
    
    assert len(results) == 4
    # Verify the exact sorting order
    assert results[0]["severity"] == "critical"
    assert results[1]["severity"] == "high"
    assert results[2]["severity"] == "medium"
    assert results[3]["severity"] == "low"
def test_dedupe_findings_normalizes_path_separators():
    findings = [
        {"title": "A", "file": r"src\app.py", "category": "bug", "line": 12, "confidence": "high"},
        {"title": "B", "file": "./src/app.py", "category": "bug", "line": 13, "confidence": "high"},
    ]

    assert len(dedupe_findings(findings)) == 1
