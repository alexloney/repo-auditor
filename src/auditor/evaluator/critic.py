import os
import json
from typing import Callable
from pathlib import Path
import ollama

from ..agent.tools import read_file, submit_verdict, make_search_code_tool
from ..utils.llm import MAX_CONTEXT, OUTPUT_RESERVE

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
    verified = []
    
    # Change working directory so tools.py correctly resolves relative paths
    original_dir = os.getcwd()
    os.chdir(target_dir)

    search_code = make_search_code_tool(extensions or [], skip_dirs or [])

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
                on_warning(f" ! Rejected finding with out-of-repo path: {file_path}")
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

            on_progress(f"Verifying {idx+1}/{len(findings)}: '{f_.get('title')}'") if on_progress else None
            
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
                        # Match the scanners' context settings. Without num_ctx, Ollama falls back to
                        # its small default window and silently truncates the prompt. num_predict
                        # leaves OUTPUT_RESERVE tokens for the model's reasoning/thinking + verdict.
                        options={
                            "temperature": 0.0,
                            "num_ctx": MAX_CONTEXT,
                            "num_predict": OUTPUT_RESERVE,
                        }
                    )
                except Exception as e:
                    on_warning(f" ! Critic call failed, keeping finding: {e}") if on_warning else None
                    verified.append(f_)
                    verdict_reached = True
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
                        is_genuine = _parse_bool(args.get("is_genuine_bug"), default=True)

                        if is_genuine:
                            adjusted = str(args.get("adjusted_severity", "")).strip().lower()
                            if adjusted in VALID_SEVERITIES:
                                f_["severity"] = adjusted
                            f_["reviewer_notes"] = args.get("reasoning", "")
                            verified.append(f_)
                            on_progress(f" - Kept: {args.get('reasoning')}") if on_progress else None
                        else:
                            on_progress(f" - Rejected: {args.get('reasoning')}") if on_progress else None
                        break

                    # Execute read_file or search_code
                    on_progress(f" > Executing: {func_name}({args})") if on_progress else None
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
                        "tool_name": func_name
                    })
                
                if verdict_reached:
                    break
            
            if not verdict_reached:
                on_warning(f" ! Hit turn limit, keeping finding by default.") if on_warning else None
                verified.append(f_)

    finally:
        os.chdir(original_dir)

    return verified
