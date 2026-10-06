import json
from typing import Callable
from pathlib import Path
import ollama

from ..agent.agent import run_agent_loop
from ..agent.tools import (
    make_read_file_tool, make_read_file_range_tool, make_search_code_tool, make_submit_verdict_tool,
)

CRITIC_MAX_TURNS = 10

CRITIC_SYSTEM_PROMPT = (
    "You are a strict, highly skeptical principal engineer reviewing automated static analysis findings. "
    "You have access to tools to read files or search the codebase if you need more context to verify the bug. "
    "Your objective is to aggressively prune false positives. "
    "CRITICAL RULES: "
    "1. Mark is_genuine_bug as false if the issue is a hallucination, relies on missing imports/context, or critiques spelling/typos. "
    "2. Mark is_genuine_bug as false if the finding is merely stylistic, pedantic, or a micro-optimization. "
    "3. If the finding is mathematically/logically real but severity is inflated, lower adjusted_severity. "
    "4. When you have enough evidence, you MUST call the `submit_verdict` tool to finalize your review."
)

CRITIC_NUDGE = "Please explore the codebase using your tools or finalize your review by calling the `submit_verdict` tool."

VALID_SEVERITIES = {"critical", "high", "medium", "low"}

def _parse_bool(value, default: bool = True) -> bool:
    """Interprets a tool-call boolean leniently; local models often send "false" as a string."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("false", "no", "0"):
            return False
        if lowered in ("true", "yes", "1"):
            return True
    return default

def _build_prompt(file_path: str, full_path: Path, content: str, finding: dict) -> str:
    lines = content.splitlines()
    target_line = finding.get("line")

    # Provide initial context so it doesn't always have to read the file first
    if isinstance(target_line, int) and 0 < target_line <= len(lines):
        start = max(0, target_line - 100)
        end = min(len(lines), target_line + 100)
        numbered_lines = [f"{start + i + 1:4d} | {line}" for i, line in enumerate(lines[start:end])]
    else:
        numbered_lines = [f"{i + 1:4d} | {line}" for i, line in enumerate(lines[:200])]

    return (
        f"File: {file_path}\n\n"
        f"```{full_path.suffix.lstrip('.')}\n" + "\n".join(numbered_lines) + "\n```\n\n"
        f"Reported Finding to verify:\n{json.dumps(finding, indent=2)}"
    )

def verify_findings(client: ollama.Client,
                    model: str,
                    target_dir: Path,
                    findings: list,
                    extensions: list[str] | None = None,
                    skip_dirs: list[str] | None = None,
                    on_progress: Callable[[str], None] = None,
                    on_warning: Callable[[str], None] = None,
                    on_error: Callable[[str], None] = None) -> list:
    """Passes each finding back to an agentic LLM equipped with code exploration tools."""
    on_progress = on_progress or (lambda _: None)
    on_warning = on_warning or (lambda _: None)
    on_error = on_error or (lambda _: None)

    root = Path(target_dir).resolve()
    read_tools = [
        make_read_file_tool(root),
        make_read_file_range_tool(root),
        make_search_code_tool(root, extensions, skip_dirs),
    ]
    verified = []

    for idx, f_ in enumerate(findings):
        file_path = f_.get("file")
        if not file_path:
            verified.append(f_)
            continue

        full_path = (root / file_path).resolve()
        if root not in full_path.parents and full_path != root:
            on_warning(f" ! Rejected finding with out-of-repo path: {file_path}")
            continue

        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            verified.append(f_)
            continue

        on_progress(f"Verifying {idx+1}/{len(findings)}: '{f_.get('title')}'")

        verdicts = []
        outcome = run_agent_loop(
            client=client,
            model=model,
            system_prompt=CRITIC_SYSTEM_PROMPT,
            initial_user_prompt=_build_prompt(file_path, full_path, content, f_),
            tools=read_tools + [make_submit_verdict_tool(verdicts.append)],
            stop_token=None,
            is_done=lambda: bool(verdicts),
            nudge_message=CRITIC_NUDGE,
            max_turns=CRITIC_MAX_TURNS,
            on_progress=on_progress,
            on_warning=on_warning,
            on_error=on_error,
        )

        if not verdicts:
            on_warning(f" ! No verdict reached ({outcome.value}), keeping finding by default.")
            verified.append(f_)
            continue

        verdict = verdicts[-1]
        if _parse_bool(verdict["is_genuine_bug"], default=True):
            adjusted = str(verdict.get("adjusted_severity") or "").strip().lower()
            if adjusted in VALID_SEVERITIES:
                f_["severity"] = adjusted
            f_["reviewer_notes"] = verdict.get("reasoning", "")
            verified.append(f_)
            on_progress(f" - Kept: {verdict.get('reasoning')}")
        else:
            on_progress(f" - Rejected: {verdict.get('reasoning')}")

    return verified
