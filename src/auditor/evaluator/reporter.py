from collections import Counter
from datetime import datetime
from pathlib import Path

def write_report(target_dir: Path, report_path: Path, findings: list) -> None:
    """Formats verified findings into a Markdown file."""
    sev_counts = Counter(f_.get("severity", "unknown") for f_ in findings)

    header = [
        f"# Static Audit Report — {target_dir.name}",
        f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}._",
        "",
        f"**Findings:** {len(findings)} total — " + ", ".join(f"{k}: {v}" for k, v in sorted(sev_counts.items())),
        "",
        "---",
        ""
    ]

    body = []
    if not findings:
        body.append("No definitive PR-worthy bugs found.")
    else:
        for f in findings:
            repro = f"\n**Steps to reproduce**\n{f.get('steps_to_reproduce')}\n" if f.get("steps_to_reproduce") else ""
            notes = f"\n> **Reviewer Notes:** {f.get('reviewer_notes')}\n" if f.get("reviewer_notes") else ""
            owasp = f" · **OWASP:** {f.get('owasp_category')}" if f.get("owasp_category") else ""
            vuln = f" · **Class:** {f.get('vuln_class')}" if f.get("vuln_class") else ""
            scanner = ""
            if f.get("scanner"):
                also = f" (also found by: {', '.join(f['also_found_by'])})" if f.get("also_found_by") else ""
                scanner = f"**Scanner:** {f['scanner']}{also}\n"
            evidence = ""
            if (f.get("evidence") or "").strip():
                lang = Path(str(f.get("file") or "")).suffix.lstrip(".")
                evidence = f"\n**Evidence**\n```{lang}\n{f['evidence'].strip()}\n```\n"

            fix = (f.get('suggested_solution') or '').strip() or 'No fix provided.'

            body.append(
                f"### {f.get('title', 'Untitled Finding')}\n"
                f"**Severity:** {f.get('severity')} · **Confidence:** {f.get('confidence', 'high')} · **Category:** {f.get('category', 'bug')}{owasp}{vuln}\n"
                f"**File:** `{f.get('file')}`:line {f.get('line') or 'n/a'}\n"
                f"{scanner}\n"
                f"**Details**\n{f.get('description')}\n"
                f"{evidence}{repro}{notes}\n"
                # The fix is written as-is, not fenced: models usually include their own code fences
                f"**Suggested solution**\n{fix}\n\n"
            )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header + body))
