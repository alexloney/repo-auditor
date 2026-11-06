from unittest.mock import MagicMock, patch

import pytest

from auditor.scanners.owasp import OwaspScanner, OWASP_CATEGORIES, normalize_cwe

RCE_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

def model_finding(**overrides):
    base = {
        "title": "SQLi", "severity": "low", "line": 1, "evidence": "q = 'SELECT ' + x",
        "description": "d", "confidence": "high", "suggested_solution": "s",
        "owasp_category": "A05:2025-Injection", "vuln_class": "CWE-89",
        "attacker_input": "query param 'x'", "trust_boundary_crossed": True,
        "exploit_preconditions": "none", "cvss_vector": RCE_VECTOR, "steps_to_reproduce": "GET /?x=' OR 1=1--",
    }
    return {**base, **overrides}

@pytest.fixture
def run_scan(tmp_path):
    """Runs the scanner on one file with the model returning `findings`; returns (recorded, scanner)."""
    (tmp_path / "app.py").write_text("q = 'SELECT ' + x\n", encoding="utf-8")

    def run(findings, **kwargs):
        recorded = []
        scanner = OwaspScanner(client=MagicMock(), model="m", target_dir=tmp_path,
                               ledger_path=tmp_path / "l.json", **kwargs)
        scanner.record_finding = recorded.append
        with patch("auditor.scanners.single_file.list_auditable_files", return_value=["app.py"]), \
             patch("auditor.scanners.single_file.call_json", return_value={"findings": findings}):
            scanner.run()
        return recorded
    return run

def test_categories_are_2025_without_supply_chain_or_logging():
    assert all(":2025-" in c for c in OWASP_CATEGORIES)
    assert not any(c.startswith(("A03", "A09")) for c in OWASP_CATEGORIES)

def test_schema_requires_attacker_model_and_poc():
    item = OwaspScanner.SCHEMA["properties"]["findings"]["items"]
    assert {
        "vuln_class", "attacker_input", "trust_boundary_crossed", "exploit_preconditions",
        "cvss_vector", "steps_to_reproduce",
    } <= set(item["required"])
    assert item["properties"]["steps_to_reproduce"]["type"] == "string"  # no longer nullable
    assert item["properties"]["vuln_class"]["pattern"] == r"^CWE-\d+$"

def test_severity_is_computed_from_cvss(run_scan):
    [finding] = run_scan([model_finding(severity="low")])

    assert finding["cvss_score"] == 9.8
    assert finding["severity"] == "critical"
    assert finding["cvss_vector"] == RCE_VECTOR
    assert finding["category"] == "security"
    assert "trust_boundary_crossed" not in finding

def test_cvss_vector_is_normalized(run_scan):
    [finding] = run_scan([model_finding(cvss_vector="av:n/ac:l/pr:l/ui:n/s:u/c:h/i:n/a:n")])

    assert finding["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
    assert finding["severity"] == "medium"  # 6.5

def test_invalid_cvss_keeps_model_severity_and_warns(run_scan):
    warnings = []
    [finding] = run_scan([model_finding(cvss_vector="9.8", severity="high")], on_warning=warnings.append)

    assert finding["severity"] == "high"
    assert "cvss_vector" not in finding and "cvss_score" not in finding
    assert any("invalid CVSS vector" in w for w in warnings)

def test_zero_impact_vector_is_dropped(run_scan):
    assert run_scan([model_finding(cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")]) == []

@pytest.mark.parametrize("value", [False, "false", "no"])
def test_findings_without_trust_boundary_are_dropped(run_scan, value):
    assert run_scan([model_finding(trust_boundary_crossed=value), model_finding(title="kept")])[0]["title"] == "kept"

def test_cwe_is_normalized(run_scan):
    [finding] = run_scan([model_finding(vuln_class="cwe 79: Cross-site Scripting")])
    assert finding["vuln_class"] == "CWE-79"

@pytest.mark.parametrize("text, expected", [
    ("CWE-89", "CWE-89"), ("CWE-079", "CWE-79"), ("cwe_22 path traversal", "CWE-22"),
    ("SQL injection", None), (None, None),
])
def test_normalize_cwe(text, expected):
    assert normalize_cwe(text) == expected
