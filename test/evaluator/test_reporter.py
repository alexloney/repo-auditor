from auditor.evaluator.reporter import write_report

def test_write_report_empty(tmp_path):
    """Verifies behavior when the evaluator prunes all findings."""
    report_path = tmp_path / "report.md"
    write_report(tmp_path, report_path, [])
    
    assert report_path.exists()
    
    content = report_path.read_text(encoding="utf-8")
    assert "Static Audit Report" in content
    assert "**Findings:** 0 total" in content
    assert "No definitive PR-worthy bugs found." in content

def test_write_report_basic_findings(tmp_path):
    """Verifies standard formatting and severity counting."""
    findings = [
        {
            "title": "SQL Injection",
            "severity": "critical",
            "category": "security",
            "file": "db.py",
            "line": 42,
            "confidence": "high",
            "description": "Unsanitized input in query.",
            "suggested_solution": "Use parameterized queries."
        },
        {
            "title": "Missing Docstring",
            "severity": "low",
            "category": "style",
            "file": "utils.py",
            "line": None,  # Testing the n/a fallback
            "description": "No docs.",
        }
    ]
    
    report_path = tmp_path / "report.md"
    write_report(tmp_path, report_path, findings)
    
    content = report_path.read_text(encoding="utf-8")
    
    # 1. Check severity counts in the header
    assert "**Findings:** 2 total" in content
    assert "critical: 1" in content
    assert "low: 1" in content
    
    # 2. Check the standard finding
    assert "### SQL Injection" in content
    assert "**Severity:** critical" in content
    assert "`db.py`:line 42" in content
    assert "Use parameterized queries." in content
    
    # 3. Check the line fallback for None values
    assert "`utils.py`:line n/a" in content

def test_write_report_optional_fields(tmp_path):
    """Verifies that optional OWASP, vulnerability classes, and reviewer notes render."""
    findings = [
        {
            "title": "XSS",
            "severity": "high",
            "file": "frontend.js",
            "owasp_category": "A03:2021-Injection",
            "vuln_class": "cross-site-scripting",
            "steps_to_reproduce": "Inject <script> into the search bar.",
            "reviewer_notes": "Confirmed in staging.",
            "suggested_solution": "Escape HTML output."
        }
    ]
    
    report_path = tmp_path / "report.md"
    write_report(tmp_path, report_path, findings)
    content = report_path.read_text(encoding="utf-8")
    
    assert "**OWASP:** A03:2021-Injection" in content
    assert "**Class:** cross-site-scripting" in content
    assert "**Steps to reproduce**\nInject <script>" in content
    assert "> **Reviewer Notes:** Confirmed in staging." in content

def test_write_report_preserves_markdown_formatting(tmp_path):
    """Verifies the reporter preserves the LLM's own markdown formatting in the solution."""
    findings = [
        {
            "title": "Missing Guard",
            "severity": "medium",
            "file": "app.py",
            # The LLM generates its own markdown, which should pass through unaltered.
            "suggested_solution": "Add a guard clause:\n```python\ndef fixed(): pass\n```"
        }
    ]
    
    report_path = tmp_path / "report.md"
    write_report(tmp_path, report_path, findings)
    content = report_path.read_text(encoding="utf-8")
    
    # Verify the solution is rendered exactly as provided, ticks and all
    expected_output = "**Suggested solution**\nAdd a guard clause:\n```python\ndef fixed(): pass\n```\n\n"
    assert expected_output in content
def test_write_report_handles_null_suggested_solution(tmp_path):
    report_path = tmp_path / "report.md"
    findings = [{"title": "Bug", "severity": "low", "file": "a.py", "description": "d", "suggested_solution": None}]

    write_report(tmp_path, report_path, findings)

    assert "No fix provided." in report_path.read_text(encoding="utf-8")

def test_write_report_shows_scanner_and_evidence(tmp_path):
    report_path = tmp_path / "report.md"
    findings = [{
        "title": "Bug", "severity": "high", "file": "src/a.py", "line": 3, "description": "d",
        "scanner": "taint", "also_found_by": ["owasp", "batch"], "evidence": "eval(x)",
    }]

    write_report(tmp_path, report_path, findings)
    text = report_path.read_text(encoding="utf-8")

    assert "**Scanner:** taint (also found by: owasp, batch)" in text
    assert "```py" in text and "eval(x)" in text
