import os
import json
from pathlib import Path
from datetime import datetime
import ollama

client = ollama.Client(host="http://192.168.86.5:11434")

# Extracted from the original .env design
CRITIC_SYSTEM_PROMPT = os.getenv("CRITIC_SYSTEM_PROMPT", (
    "You are a strict, highly skeptical principal engineer reviewing automated static analysis findings. "
    "You will receive a file snippet and a reported bug. Your objective is to aggressively prune false positives. "
    "CRITICAL RULES: "
    "1. Mark is_genuine_bug as false if the issue is a hallucination, relies on missing imports/context, or critiques spelling/typos. "
    "2. Mark is_genuine_bug as false if the finding is merely stylistic, pedantic, or a micro-optimization. "
    "3. If the finding is mathematically/logically real but severity is inflated, lower adjusted_severity."
))

VERIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "is_genuine_bug": {"type": "boolean"},
        "reasoning": {"type": "string"},
        "adjusted_severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]}
    },
    "required": ["is_genuine_bug", "reasoning", "adjusted_severity"]
}

def dedupe(findings: list) -> list:
    """Groups findings by file, category, and approximate line number to remove duplicates."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    best = {}
    
    for f_ in findings:
        line_val = f_.get("line")
        approx_line = line_val // 10 if isinstance(line_val, int) else 0
        key = (f_.get("file"), f_.get("category"), approx_line)
        
        cur = best.get(key)
        if cur is None or conf_rank.get(f_.get("confidence"), 9) < conf_rank.get(cur.get("confidence"), 9):
            best[key] = f_
            
    out = list(best.values())
    out.sort(key=lambda f_: order.get(f_.get("severity"), 9))
    return out

def verify_findings(target_dir: Path, findings: list, model: str) -> list:
    """Passes each finding back to the LLM with a +/- 100 line context window."""
    verified = []
    
    for idx, f_ in enumerate(findings):
        file_path = f_.get("file")
        if not file_path:
            # No file to verify against; keep the finding as-is
            verified.append(f_)
            continue

        full_path = (target_dir / file_path).resolve()
        if target_dir.resolve() not in full_path.parents and full_path != target_dir.resolve():
            print(f"    ! Rejected finding with out-of-repo path: {file_path}")
            continue

        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as file_obj:
                content = file_obj.read()
        except OSError:
            # Keep finding if the file cannot be read
            verified.append(f_)
            continue

        lines = content.splitlines()
        target_line = f_.get("line")
        
        # Truncate to +/- 100 lines around the reported bug to save tokens
        if isinstance(target_line, int) and 0 < target_line <= len(lines):
            start = max(0, target_line - 100)
            end = min(len(lines), target_line + 100)
            context_lines = lines[start:end]
            numbered_lines = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(context_lines)]
        else:
            numbered_lines = [f"{i + 1:4d} | {line}" for i, line in enumerate(lines[:200])]

        chunk_text = "\n".join(numbered_lines)
        finding_payload = json.dumps(f_, indent=2)
        
        user_prompt = (
            f"File: {file_path}\n\n"
            f"```{full_path.suffix.lstrip('.')}\n{chunk_text}\n```\n\n"
            f"Reported Finding to verify:\n{finding_payload}"
        )

        print(f"  [Evaluator] Verifying {idx+1}/{len(findings)}: '{f_.get('title')}'")
        try:
            resp = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                format=VERIFICATION_SCHEMA,
                options={"temperature": 0.0}
            )
            
            res = json.loads(resp.message.content)
            
            if res.get("is_genuine_bug"):
                f_["severity"] = res.get("adjusted_severity", f_.get("severity", "medium"))
                f_["reviewer_notes"] = res.get("reasoning", "")
                verified.append(f_)
            else:
                print(f"    - Rejected: {res.get('reasoning')}")
                
        except Exception as e:
            print(f"    ! Critic call failed, keeping finding: {e}")
            verified.append(f_)

    return verified

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

            body.append(
                f"### {f.get('title', 'Untitled Finding')}\n"
                f"**Severity:** {f.get('severity')} · **Confidence:** {f.get('confidence', 'high')} · **Category:** {f.get('category', 'bug')}{owasp}\n"
                f"**File:** `{f.get('file')}`:line {f.get('line') or 'n/a'}\n\n"
                f"**Details**\n{f.get('description')}\n"
                f"{repro}{notes}\n"
                f"**Suggested solution**\n```\n{f.get('suggested_solution', 'No fix provided.')}\n```\n\n"
            )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header + body))
    
    print(f"  [Evaluator] Report written -> {report_path}")

def run_evaluation(target_dir: Path, ledger_path: Path):
    """Entry point for the evaluation pass."""
    model = os.getenv("MODEL", "qwen-coder-64k:latest")
    
    if not ledger_path.exists():
        print("  [Evaluator] No findings.json ledger found. Skipping evaluation.")
        return

    raw_findings = []
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    raw_findings.append(json.loads(line))
                except json.JSONDecodeError:
                    print(f"  [Evaluator] Skipping malformed ledger entry at line {lineno}")
    except OSError as e:
        print(f"  [Evaluator] Failed to read ledger: {e}")
        return

    print(f"  [Evaluator] Loaded {len(raw_findings)} raw findings.")
    
    unique_findings = dedupe(raw_findings)
    print(f"  [Evaluator] {len(unique_findings)} unique finding(s) before verification.")
    
    if unique_findings:
        verified_findings = verify_findings(target_dir, unique_findings, model)
        print(f"  [Evaluator] {len(verified_findings)} finding(s) survived critic pass.")
    else:
        verified_findings = []
        
    write_report(target_dir, verified_findings)