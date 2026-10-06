import os
from pathlib import Path
from datetime import datetime
import json

def write_report(target_dir: Path, findings: list) -> None:
    """Formats verified findings into a Markdown file."""
    report_path = target_dir / "report.md"
    
    sev_counts = {}
    for f_ in findings:
        sev = f_.get("severity", "unknown")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

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
            
            # Remove the stripping logic, just ensure it isn't empty
            fix = f.get('suggested_solution', 'No fix provided.').strip()

            body.append(
                f"### {f.get('title', 'Untitled Finding')}\n"
                f"**Severity:** {f.get('severity')} · **Confidence:** {f.get('confidence', 'high')} · **Category:** {f.get('category', 'bug')}{owasp}{vuln}\n"
                f"**File:** `{f.get('file')}`:line {f.get('line') or 'n/a'}\n"
                f"{scanner}\n"
                f"**Details**\n{f.get('description')}\n"
                f"{evidence}{repro}{notes}\n"
                # Output the LLM's string exactly as-is without wrapping it in your own ticks
                f"**Suggested solution**\n{fix}\n\n"
            )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header + body))
