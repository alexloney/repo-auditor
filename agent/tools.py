import os
import json
from pathlib import Path

# Keep a wide safety margin below the 66k context window so a single huge file
# can't blow the whole conversation budget on its own.
MAX_READ_TOKENS = 15000
MAX_SEARCH_RESULTS = 100

def _estimate_tokens(text: str) -> int:
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        # Matches scanners.common.estimate_tokens; source code tokenizes denser than prose.
        return max(1, len(text) // 3)

# The agent's cwd is chdir'd to the target repo root before the tool loop starts.
# All paths are resolved against that root and must not escape it, since the repo
# content the agent reads is untrusted and could try to steer it (prompt injection)
# into reading or listing files elsewhere on disk.
def _resolve_within_root(path_str: str) -> Path:
    root = Path.cwd().resolve()
    candidate = (root / path_str).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"Path '{path_str}' escapes the repository root")
    return candidate

def list_files(directory: str) -> str:
    """
    Lists all files and folders in the given directory. 
    Use '.' to list the current directory.
    """
    try:
        target = _resolve_within_root(directory)
        items = os.listdir(target)
        return json.dumps({"directory": directory, "contents": items})
    except Exception as e:
        return f"Error reading directory: {str(e)}"

def read_file(filepath: str) -> str:
    """
    Reads the complete contents of a specific source code file.
    """
    try:
        target = _resolve_within_root(filepath)
        with open(target, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        if _estimate_tokens(content) > MAX_READ_TOKENS:
            return "File too large to read entirely. Skip this file."
        return content
    except Exception as e:
        return f"Error reading file '{filepath}': {str(e)}"

def read_file_range(filepath: str, start_line: int, end_line: int) -> str:
    """
    Reads a specific 1-indexed, inclusive line range of a source file, prefixed with line numbers.
    Use this to inspect a region of a file that is too large to read in full.
    """
    try:
        target = _resolve_within_root(filepath)
        with open(target, 'r', encoding='utf-8', errors='replace') as f:
            lines = f.read().splitlines()

        start = max(1, int(start_line))
        end = min(len(lines), int(end_line))
        if start > len(lines):
            return f"File '{filepath}' only has {len(lines)} lines."
        if end < start:
            end = start

        selected = [f"{i:4d} | {lines[i - 1]}" for i in range(start, end + 1)]
        snippet = "\n".join(selected)
        if _estimate_tokens(snippet) > MAX_READ_TOKENS:
            return "Requested range is too large. Request a narrower line range."
        return snippet
    except Exception as e:
        return f"Error reading file '{filepath}': {str(e)}"

def search_code(query: str, directory: str = ".") -> str:
    """
    Searches for a specific text string across all files in the directory.
    Returns the file path, line number, and the matching line of code.
    """
    try:
        target = _resolve_within_root(directory)
        results = []
        truncated = False
        for root, dirs, files in os.walk(target):
            # Skip hidden directories like .git (prune in-place so os.walk doesn't descend)
            dirs[:] = [d for d in dirs if not d.startswith('.')]

            for file in files:
                path = Path(root) / file

                # Skip binaries or large media
                if path.suffix in ['.png', '.jpg', '.exe', '.dll', '.so']:
                    continue

                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f):
                            if query in line:
                                rel_path = path.relative_to(Path.cwd().resolve())
                                results.append(f"{rel_path}:{i+1}: {line.strip()[:300]}")
                                if len(results) >= MAX_SEARCH_RESULTS:
                                    truncated = True
                                    break
                except Exception:
                    continue

                if truncated:
                    break
            if truncated:
                break

        if not results:
            return f"No matches found for '{query}'."
        if truncated:
            results.append(f"... results truncated at {MAX_SEARCH_RESULTS} matches. Use a more specific query.")
        return "\n".join(results)
    except Exception as e:
        return f"Error searching code: {str(e)}"

def report_issue(
    filepath: str,
    line: int,
    title: str,
    description: str,
    severity: str = "medium",
    category: str = "bug",
    suggested_solution: str = "",
) -> str:
    """
    Logs a discovered bug, vulnerability, or bad practice into the ledger.
    You must provide the filepath, the exact line number, a short title, a detailed
    description, a severity ("critical", "high", "medium", or "low"), a category
    (e.g. "bug", "security", "performance"), and a suggested fix.
    """
    # Fetch the ledger path from the environment; the scanner sets this before running.
    ledger_path = os.environ.get("AUDIT_LEDGER_PATH", "audit_ledger.json")

    try:
        with open(ledger_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps({
                "file": filepath,
                "line": line,
                "title": title,
                "description": description,
                "severity": severity,
                "confidence": "high",
                "category": category,
                "suggested_solution": suggested_solution,
            }) + '\n')
        return "Issue successfully logged to the ledger."
    except Exception as e:
        return f"Error logging issue: {str(e)}"