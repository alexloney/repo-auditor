import pytest
from pathlib import Path
from auditor.evaluator.reporter import write_report

def test_write_report_empty(tmp_path):
    """Verifies behavior when the evaluator prunes all findings."""
    write_report(tmp_path, [])
    
    report_file = tmp_path / "report.md"
    assert report_file.exists()
    
    content = report_file.read_text(encoding="utf-8")
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
    
    write_report(tmp_path, findings)
    
    content = (tmp_path / "report.md").read_text(encoding="utf-8")
    
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
    
    write_report(tmp_path, findings)
    content = (tmp_path / "report.md").read_text(encoding="utf-8")
    
    assert "**OWASP:** A03:2021-Injection" in content
    assert "**Class:** cross-site-scripting" in content
    assert "**Steps to reproduce**\nInject <script>" in content
    assert "> **Reviewer Notes:** Confirmed in staging." in content

def test_write_report_strips_nested_markdown_ticks(tmp_path):
    """Verifies the reporter prevents broken markdown blocks if the LLM includes ``` in the solution."""
    findings = [
        {
            "title": "Bad Fences",
            "severity": "medium",
            "file": "app.py",
            # The LLM wraps the code in ```python ... ```, which would break the reporter's own ``` wrap.
            "suggested_solution": "```python\ndef fixed(): pass\n```"
        }
    ]
    
    write_report(tmp_path, findings)
    content = (tmp_path / "report.md").read_text(encoding="utf-8")
    
    # The stripping logic should remove the backticks and trailing spaces, leaving only the inner code block
    # wrapped safely inside the reporter's own template fences.
    assert "```\npython\ndef fixed(): pass\n```" in content