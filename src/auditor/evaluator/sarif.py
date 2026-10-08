"""SARIF 2.1.0 output, for GitHub code scanning, the VS Code SARIF Viewer and similar tools."""
import hashlib
import json
import re
from importlib import metadata
from pathlib import Path
from urllib.parse import quote

from ..utils.filesystem import normalize_relpath

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "repo-auditor"

# SARIF levels: error / warning / note
LEVELS = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}

# GitHub code scanning reads `security-severity` (0.0-10.0) on security-tagged rules to
# rank alerts as critical (>= 9.0), high (>= 7.0), medium (>= 4.0) or low.
SECURITY_SEVERITY = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0}

def _tool_version() -> str:
    try:
        return metadata.version(TOOL_NAME)
    except metadata.PackageNotFoundError:
        return "0.0.0"

def _rule_id(finding: dict) -> str:
    """Groups findings into rules: '<scanner>/<most specific classification>'."""
    scanner = finding.get("scanner") or TOOL_NAME
    vuln_class = finding.get("vuln_class") or ""
    # Prefer the OWASP category, then a slug-style vulnerability class (memory scanner's enum),
    # then the general category. Free-text classes would explode the number of rules.
    kind = (finding.get("owasp_category")
            or (vuln_class if re.fullmatch(r"[a-z0-9-]+", vuln_class) else "")
            or finding.get("category")
            or "bug")
    return f"{scanner}/{kind}"

def _fingerprint(finding: dict) -> str:
    """Stable across runs and line shifts, so tools can track the same alert over time."""
    def norm(value) -> str:
        return " ".join(str(value or "").lower().split())
    key = "|".join((norm(finding.get("file")), norm(finding.get("title")), norm(finding.get("evidence"))))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

def _markdown(finding: dict) -> str:
    parts = [f"**{finding.get('title') or 'Untitled finding'}**", "", str(finding.get("description") or "")]
    if finding.get("steps_to_reproduce"):
        parts += ["", "**Steps to reproduce**", str(finding["steps_to_reproduce"])]
    if finding.get("reviewer_notes"):
        parts += ["", f"> **Reviewer notes:** {finding['reviewer_notes']}"]
    if (finding.get("suggested_solution") or "").strip():
        parts += ["", "**Suggested solution**", finding["suggested_solution"].strip()]
    return "\n".join(parts)

def _location(finding: dict) -> dict | None:
    file_path = normalize_relpath(finding.get("file"))
    if not file_path:
        return None
    physical = {"artifactLocation": {"uri": quote(file_path), "uriBaseId": "SRCROOT"}}
    line = finding.get("line")
    if isinstance(line, int) and not isinstance(line, bool) and line >= 1:
        region = {"startLine": line}
        if (finding.get("evidence") or "").strip():
            region["snippet"] = {"text": finding["evidence"].strip()}
        physical["region"] = region
    return {"physicalLocation": physical}

def _properties(finding: dict) -> dict:
    keys = {
        "severity": "severity", "confidence": "confidence", "category": "category",
        "scanner": "scanner", "also_found_by": "alsoFoundBy", "owasp_category": "owaspCategory",
        "vuln_class": "vulnClass", "reviewer_notes": "reviewerNotes",
        "suggested_solution": "suggestedSolution", "steps_to_reproduce": "stepsToReproduce",
    }
    return {out: finding[key] for key, out in keys.items() if finding.get(key)}

def build_sarif(target_dir: Path, findings: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    results = []

    for finding in findings:
        rule_id = _rule_id(finding)
        severity = finding.get("severity")
        rule = rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": rule_id},
            "properties": {"tags": []},
        })
        is_security = finding.get("category") == "security"
        if is_security and "security" not in rule["properties"]["tags"]:
            rule["properties"]["tags"].append("security")
        if is_security and severity in SECURITY_SEVERITY:
            # A rule covers many results; GitHub ranks by the rule, so keep the worst seen.
            current = float(rule["properties"].get("security-severity", "0"))
            rule["properties"]["security-severity"] = str(max(current, SECURITY_SEVERITY[severity]))

        title = finding.get("title") or "Untitled finding"
        description = finding.get("description") or ""
        result = {
            "ruleId": rule_id,
            "level": LEVELS.get(severity, "warning"),
            "message": {
                "text": f"{title}: {description}" if description else title,
                "markdown": _markdown(finding),
            },
            "partialFingerprints": {"repoAuditor/v1": _fingerprint(finding)},
            "properties": _properties(finding),
        }
        location = _location(finding)
        if location:
            result["locations"] = [location]
        results.append(result)

    rule_list = list(rules.values())
    rule_index = {rule["id"]: i for i, rule in enumerate(rule_list)}
    for result in results:
        result["ruleIndex"] = rule_index[result["ruleId"]]

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": _tool_version(),
                "rules": rule_list,
            }},
            "originalUriBaseIds": {"SRCROOT": {"uri": Path(target_dir).resolve().as_uri() + "/"}},
            "results": results,
        }],
    }

def write_sarif_report(target_dir: Path, report_path: Path, findings: list[dict]) -> None:
    """Writes verified findings as a SARIF 2.1.0 log."""
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(build_sarif(target_dir, findings), f, indent=2, ensure_ascii=False)
