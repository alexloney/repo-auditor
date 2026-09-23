import os
import json
from pathlib import Path
from datetime import datetime
import ollama

from agent.tools import read_file, search_code

# Updated system prompt to guide the tool-calling behavior
CRITIC_SYSTEM_PROMPT = os.getenv("CRITIC_SYSTEM_PROMPT", (
    "You are a strict, highly skeptical principal engineer reviewing automated static analysis findings. "
    "You have access to tools to read files or search the codebase if you need more context to verify the bug. "
    "Your objective is to aggressively prune false positives. "
    "CRITICAL RULES: "
    "1. Mark is_genuine_bug as false if the issue is a hallucination, relies on missing imports/context, or critiques spelling/typos. "
    "2. Mark is_genuine_bug as false if the finding is merely stylistic, pedantic, or a micro-optimization. "
    "3. If the finding is mathematically/logically real but severity is inflated, lower adjusted_severity. "
    "4. When you have enough evidence, you MUST call the `submit_verdict` tool to finalize your review."
))

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

def submit_verdict(is_genuine_bug: bool, reasoning: str, adjusted_severity: str) -> str:
    """
    Submits your final verdict on whether the reported bug is real.
    You must call this tool to complete the evaluation of the current finding.
    
    :param is_genuine_bug: True if it is a real bug, False if it is a false positive.
    :param reasoning: A concise explanation of why it was kept or rejected.
    :param adjusted_severity: Must be "critical", "high", "medium", or "low".
    """
    return "Verdict received."

def verify_findings(client: ollama.Client, target_dir: Path, findings: list, model: str) -> list:
    """Passes each finding back to an agentic LLM equipped with code exploration tools."""
    verified = []
    
    # Change working directory so tools.py correctly resolves relative paths
    original_dir = os.getcwd()
    os.chdir(target_dir)

    tools = [read_file, search_code, submit_verdict]
    available_tools = {t.__name__: t for t in tools}

    try:
        for idx, f_ in enumerate(findings):
            file_path = f_.get("file")
            if not file_path:
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
                verified.append(f_)
                continue

            lines = content.splitlines()
            target_line = f_.get("line")
            
            # Provide initial context so it doesn't always have to read the file first
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
            
            messages = [
                {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

            # Bounded agent loop for a single finding
            verdict_reached = False
            for turn in range(10):
                try:
                    resp = client.chat(
                        model=model,
                        messages=messages,
                        tools=tools,
                        options={"temperature": 0.0}
                    )
                except Exception as e:
                    print(f"    ! Critic call failed, keeping finding: {e}")
                    verified.append(f_)
                    break

                msg = resp.message
                
                # If the agent responds without calling a tool, nudge it
                if not getattr(msg, 'tool_calls', None):
                    messages.append(msg)
                    messages.append({
                        "role": "user", 
                        "content": "Please explore the codebase using your tools or finalize your review by calling the `submit_verdict` tool."
                    })
                    continue

                messages.append(msg)

                for call in msg.tool_calls:
                    func_name = call.function.name
                    args = call.function.arguments
                    
                    if func_name == "submit_verdict":
                        verdict_reached = True
                        is_genuine = args.get("is_genuine_bug", True)
                        
                        if is_genuine:
                            f_["severity"] = args.get("adjusted_severity", f_.get("severity", "medium"))
                            f_["reviewer_notes"] = args.get("reasoning", "")
                            verified.append(f_)
                            print(f"    - Kept: {args.get('reasoning')}")
                        else:
                            print(f"    - Rejected: {args.get('reasoning')}")
                        break

                    # Execute read_file or search_code
                    print(f"    > Evaluator Executing: {func_name}({args})")
                    if func_name in available_tools:
                        try:
                            result = available_tools[func_name](**args)
                        except Exception as e:
                            result = f"Execution error: {e}"
                    else:
                        result = f"Error: Tool {func_name} not found."

                    messages.append({
                        "role": "tool",
                        "content": str(result),
                        "name": func_name
                    })
                
                if verdict_reached:
                    break
            
            if not verdict_reached:
                print(f"    ! Evaluator hit turn limit, keeping finding by default.")
                verified.append(f_)

    finally:
        os.chdir(original_dir)

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
            vuln = f" · **Class:** {f.get('vuln_class')}" if f.get("vuln_class") else ""
            
            # Clean up nested markdown ticks
            fix = f.get('suggested_solution', 'No fix provided.')
            fix = fix.strip("`").strip() if fix.startswith("```") else fix

            body.append(
                f"### {f.get('title', 'Untitled Finding')}\n"
                f"**Severity:** {f.get('severity')} · **Confidence:** {f.get('confidence', 'high')} · **Category:** {f.get('category', 'bug')}{owasp}{vuln}\n"
                f"**File:** `{f.get('file')}`:line {f.get('line') or 'n/a'}\n\n"
                f"**Details**\n{f.get('description')}\n"
                f"{repro}{notes}\n"
                f"**Suggested solution**\n```\n{fix}\n```\n\n"
            )

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(header + body))
    
    print(f"  [Evaluator] Report written -> {report_path}")

def run_evaluation(client: ollama.Client, target_dir: Path, ledger_path: Path):
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
        verified_findings = verify_findings(client, target_dir, unique_findings, model)
        print(f"  [Evaluator] {len(verified_findings)} finding(s) survived critic pass.")
    else:
        verified_findings = []
        
    write_report(target_dir, verified_findings)