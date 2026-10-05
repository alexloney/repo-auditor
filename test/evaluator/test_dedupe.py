from auditor.evaluator.dedupe import dedupe_findings, LINE_WINDOW

def test_dedupe_merges_same_bug_on_nearby_lines():
    findings = [
        {"title": "Off-by-one in loop bound", "file": "app.py", "category": "bug", "line": 12, "confidence": "high", "severity": "medium"},
        {"title": "Loop boundary off-by-one error", "file": "app.py", "category": "correctness", "line": 15, "confidence": "high", "severity": "medium"},
    ]

    results = dedupe_findings(findings)

    # Different (free-text) categories still merge: the title and location match.
    assert len(results) == 1
    assert results[0]["title"] == "Off-by-one in loop bound"  # The first one wins on a tie

def test_dedupe_merges_across_old_bucket_boundary():
    """Lines 9 and 10 used to land in different line // 10 buckets."""
    findings = [
        {"title": "Unclosed file handle", "file": "app.py", "line": 9},
        {"title": "File handle never closed", "file": "app.py", "line": 10},
    ]

    assert len(dedupe_findings(findings)) == 1

def test_dedupe_keeps_different_bugs_on_nearby_lines():
    findings = [
        {"title": "Off-by-one in loop bound", "file": "app.py", "category": "bug", "line": 12},
        {"title": "Division by zero when list is empty", "file": "app.py", "category": "bug", "line": 14},
    ]

    assert len(dedupe_findings(findings)) == 2

def test_dedupe_keeps_same_title_far_apart():
    findings = [
        {"title": "SQL injection in query", "file": "app.py", "line": 10},
        {"title": "SQL injection in query", "file": "app.py", "line": 10 + LINE_WINDOW + 1},
    ]

    assert len(dedupe_findings(findings)) == 2

def test_dedupe_keeps_different_files():
    findings = [
        {"title": "SQL injection in query", "file": "app.py", "line": 12},
        {"title": "SQL injection in query", "file": "utils.py", "line": 12},
    ]

    assert len(dedupe_findings(findings)) == 2

def test_dedupe_prefers_higher_confidence():
    findings = [
        {"title": "Command injection via shell", "file": "app.py", "line": 45, "confidence": "low", "severity": "critical"},
        {"title": "Shell command injection", "file": "app.py", "line": 48, "confidence": "high", "severity": "medium"},
        {"title": "Command injection in shell call", "file": "app.py", "line": 41, "confidence": "medium", "severity": "high"},
    ]

    results = dedupe_findings(findings)

    assert len(results) == 1
    assert results[0]["confidence"] == "high"
    assert results[0]["severity"] == "medium"

def test_dedupe_prefers_higher_severity_on_confidence_tie():
    findings = [
        {"title": "Race on shared counter", "file": "app.py", "line": 5, "confidence": "high", "severity": "low"},
        {"title": "Shared counter race", "file": "app.py", "line": 6, "confidence": "high", "severity": "high"},
    ]

    assert dedupe_findings(findings)[0]["severity"] == "high"

def test_dedupe_findings_without_lines_compare_titles_only():
    findings = [
        {"title": "Hardcoded secret key", "file": "app.py", "line": None, "confidence": "low"},
        {"title": "Unbounded recursion in parser", "file": "app.py", "confidence": "high"},
        {"title": "Secret key hardcoded in source", "file": "app.py", "line": 30, "confidence": "high"},
    ]

    results = dedupe_findings(findings)

    # The two unrelated no-line findings no longer collapse into one; the secret-key pair does.
    assert len(results) == 2
    titles = {f["title"] for f in results}
    assert titles == {"Unbounded recursion in parser", "Secret key hardcoded in source"}

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
        {"title": "Unchecked return value", "file": r"src\app.py", "line": 12, "confidence": "high"},
        {"title": "Return value unchecked", "file": "./src/app.py", "line": 13, "confidence": "high"},
    ]

    assert len(dedupe_findings(findings)) == 1
