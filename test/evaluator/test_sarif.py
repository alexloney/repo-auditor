import json

from auditor.evaluator.sarif import build_sarif, write_sarif_report

def finding(**overrides):
    base = {
        "title": "SQL injection", "file": "web/app.py", "line": 12, "evidence": "cur.execute(q + uid)",
        "severity": "high", "category": "security", "scanner": "taint", "description": "Untrusted uid.",
    }
    return {**base, **overrides}

def run_of(findings, tmp_path):
    return build_sarif(tmp_path, findings)["runs"][0]

def test_sarif_document_shape(tmp_path):
    doc = build_sarif(tmp_path, [finding()])

    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "repo-auditor"
    assert run["originalUriBaseIds"]["SRCROOT"]["uri"] == tmp_path.resolve().as_uri() + "/"

def test_sarif_result_location_and_snippet(tmp_path):
    result = run_of([finding(file="web/my app.py")], tmp_path)["results"][0]

    physical = result["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"] == {"uri": "web/my%20app.py", "uriBaseId": "SRCROOT"}
    assert physical["region"] == {"startLine": 12, "snippet": {"text": "cur.execute(q + uid)"}}
    assert result["message"]["text"].startswith("SQL injection: Untrusted uid.")

def test_sarif_levels_follow_severity(tmp_path):
    findings = [finding(severity=s, title=s) for s in ("critical", "high", "medium", "low")]
    levels = [r["level"] for r in run_of(findings, tmp_path)["results"]]
    assert levels == ["error", "error", "warning", "note"]

def test_sarif_rules_are_shared_and_indexed(tmp_path):
    findings = [
        finding(severity="medium"),
        finding(title="Other SQLi", severity="critical"),
        finding(scanner="memory", vuln_class="buffer-overflow", title="Overflow"),
        finding(scanner="owasp", owasp_category="A03:2021-Injection", vuln_class="SQL injection"),
        finding(scanner="single-file", category="bug", title="Bug"),
    ]
    run = run_of(findings, tmp_path)
    rules = run["tool"]["driver"]["rules"]

    assert [r["id"] for r in rules] == [
        "taint/security", "memory/buffer-overflow", "owasp/A03:2021-Injection", "single-file/bug",
    ]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
    # Worst severity seen wins for the rule; only security rules carry it
    assert rules[0]["properties"] == {"tags": ["security"], "security-severity": "9.5"}
    assert "security-severity" not in rules[3]["properties"]

def test_sarif_omits_region_without_line_and_location_without_file(tmp_path):
    results = run_of([finding(line=None), finding(file=None, title="x")], tmp_path)["results"]

    assert "region" not in results[0]["locations"][0]["physicalLocation"]
    assert "locations" not in results[1]

def test_sarif_fingerprint_is_stable_across_line_shifts(tmp_path):
    a = run_of([finding(line=12)], tmp_path)["results"][0]["partialFingerprints"]
    b = run_of([finding(line=40)], tmp_path)["results"][0]["partialFingerprints"]
    c = run_of([finding(title="Different")], tmp_path)["results"][0]["partialFingerprints"]
    assert a == b != c

def test_sarif_properties_carry_auditor_fields(tmp_path):
    props = run_of([finding(also_found_by=["owasp"], reviewer_notes="Confirmed", suggested_solution="Use params")],
                   tmp_path)["results"][0]["properties"]

    assert props["scanner"] == "taint"
    assert props["alsoFoundBy"] == ["owasp"]
    assert props["reviewerNotes"] == "Confirmed"
    assert props["suggestedSolution"] == "Use params"

def test_write_sarif_report_writes_json(tmp_path):
    path = tmp_path / "report.sarif"
    write_sarif_report(tmp_path, path, [finding()])

    assert json.loads(path.read_text(encoding="utf-8"))["runs"][0]["results"][0]["ruleId"] == "taint/security"

def test_sarif_empty_findings(tmp_path):
    run = run_of([], tmp_path)
    assert run["results"] == [] and run["tool"]["driver"]["rules"] == []
