import os
import json
from pathlib import Path
from typing import Callable

from ..utils.llm import estimate_tokens
from ..utils.filesystem import number_lines
from .coverage import ReadCoverage

# Keep a wide safety margin below the 66k context window so a single huge file
# can't blow the whole conversation budget on its own.
MAX_READ_TOKENS = 15000
MAX_SEARCH_RESULTS = 100

# Every tool is built by a factory that closes over the repository root. All paths
# are resolved against that root and must not escape it, since the repo content the
# agent reads is untrusted and could try to steer it (prompt injection) into reading
# or listing files elsewhere on disk.
def _resolve_within_root(root: Path, path_str: str) -> Path:
    # Agents often emit Windows-style backslashes; treat them as separators on any OS.
    candidate = (root / path_str.replace("\\", "/")).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"Path '{path_str}' escapes the repository root")
    return candidate

def make_read_file_tool(root: Path, coverage: ReadCoverage | None = None):
    root = Path(root).resolve()

    def read_file(filepath: str) -> str:
        """
        Reads the complete contents of a specific source code file, prefixed with line numbers.

        Args:
            filepath: Path of the file to read, relative to the repository root.
        """
        try:
            target = _resolve_within_root(root, filepath)
            with open(target, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            numbered_content = number_lines(content)
            if estimate_tokens(numbered_content) > MAX_READ_TOKENS:
                return "File too large to read entirely. Use read_file_range to read it in sections."
            if coverage is not None:
                coverage.record_full(target.relative_to(root).as_posix())
            return numbered_content
        except Exception as e:
            return f"Error reading file '{filepath}': {str(e)}"

    return read_file

def make_read_file_range_tool(root: Path, coverage: ReadCoverage | None = None):
    root = Path(root).resolve()

    def read_file_range(filepath: str, start_line: int, end_line: int) -> str:
        """
        Reads a specific 1-indexed, inclusive line range of a source file, prefixed with line numbers.
        Use this to inspect a region of a file that is too large to read in full.

        Args:
            filepath: Path of the file to read, relative to the repository root.
            start_line: First line to return (1-indexed, inclusive).
            end_line: Last line to return (1-indexed, inclusive).
        """
        try:
            target = _resolve_within_root(root, filepath)
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
            if estimate_tokens(snippet) > MAX_READ_TOKENS:
                return "Requested range is too large. Request a narrower line range."
            if coverage is not None:
                coverage.record_range(target.relative_to(root).as_posix(), start, end)
            return snippet
        except Exception as e:
            return f"Error reading file '{filepath}': {str(e)}"

    return read_file_range

def make_list_files_tool(root: Path, extensions: list[str] | None, skip_dirs: list[str] | None):
    root = Path(root).resolve()
    skip_set = set(skip_dirs) if skip_dirs else set()
    ext_set = set(extensions) if extensions else None

    def list_files(directory: str) -> str:
        """
        Lists all files and folders in the given directory. Folders end with a trailing '/'.

        Args:
            directory: Directory to list, relative to the repository root. Use '.' for the root.
        """
        try:
            target = _resolve_within_root(root, directory)
            items = os.listdir(target)
            filtered = []

            for item in items:
                path = target / item
                if path.is_dir():
                    if item.startswith('.') or item in skip_set:
                        continue
                    # Appending a trailing slash helps the agent distinguish directories
                    filtered.append(item + "/")
                else:
                    if ext_set is not None and path.suffix not in ext_set:
                        continue
                    filtered.append(item)

            return json.dumps({"directory": directory, "contents": filtered})
        except Exception as e:
            return f"Error reading directory: {str(e)}"

    return list_files


def make_search_code_tool(root: Path, extensions: list[str] | None, skip_dirs: list[str] | None):
    root = Path(root).resolve()
    skip_set = set(skip_dirs) if skip_dirs else set()
    ext_set = set(extensions) if extensions else None

    def search_code(query: str, directory: str = ".") -> str:
        """
        Searches for a specific text string across all files in the directory.
        Returns the file path, line number, and the matching line of code.

        Args:
            query: Exact, case-sensitive text to search for (not a regex).
            directory: Directory to search recursively, relative to the repository root. Defaults to '.'.
        """
        try:
            target = _resolve_within_root(root, directory)
            results = []
            truncated = False

            for dirpath, dirs, files in os.walk(target):
                # Prune hidden directories and user-defined skip directories in-place
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_set]

                for file in files:
                    path = Path(dirpath) / file

                    # Apply extension filtering
                    if ext_set is not None and path.suffix not in ext_set:
                        continue

                    # Fallback binary filter
                    if path.suffix in ['.png', '.jpg', '.exe', '.dll', '.so']:
                        continue

                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            for i, line in enumerate(f):
                                if query in line:
                                    rel_path = path.relative_to(root).as_posix()
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

    return search_code


def make_report_issue_tool(root: Path, ledger_path: Path):
    root = Path(root).resolve()

    def report_issue(
        filepath: str,
        line: int,
        title: str,
        description: str,
        severity: str = "medium",
        confidence: str = "high",
        category: str = "bug",
        suggested_solution: str = "",
    ) -> str:
        """
        Logs a discovered bug, vulnerability, or bad practice into the ledger.

        Args:
            filepath: Path of the file containing the issue, relative to the repository root.
            line: Exact 1-indexed line number where the issue occurs.
            title: Short, specific name of the issue.
            description: Detailed explanation of the defect and why it is a real problem.
            severity: One of "critical", "high", "medium", or "low".
            confidence: How certain you are the issue is real. One of "high", "medium", or "low".
            category: Kind of issue, e.g. "bug", "security", "resource-leak", "race-condition", "performance", "correctness", or "api-misuse".
            suggested_solution: Concrete minimal fix, ideally as a code snippet.
        """

        # Normalize to a repo-relative, forward-slash path so agent findings dedupe against
        # other scanners' findings, and reject paths outside the repository.
        try:
            target = _resolve_within_root(root, filepath)
        except ValueError as e:
            return f"Error logging issue: {e}. Use a path relative to the repository root."
        rel_path = target.relative_to(root).as_posix()

        try:
            with open(ledger_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps({
                    "file": rel_path,
                    "line": line,
                    "title": title,
                    "description": description,
                    "severity": severity,
                    "confidence": confidence,
                    "category": category,
                    "suggested_solution": suggested_solution,
                }) + '\n')
            return "Issue successfully logged to the ledger."
        except Exception as e:
            return f"Error logging issue: {str(e)}"
    return report_issue


def make_submit_verdict_tool(on_verdict: Callable[[dict], None]):
    """Builds the critic's verdict tool; each call hands the raw arguments to on_verdict."""

    def submit_verdict(is_genuine_bug: bool, reasoning: str, adjusted_severity: str = "") -> str:
        """
        Submits your final verdict on whether the reported bug is real.
        You must call this tool to complete the evaluation of the current finding.

        Args:
            is_genuine_bug: true if it is a real bug, false if it is a false positive.
            reasoning: A concise explanation of why it was kept or rejected.
            adjusted_severity: One of "critical", "high", "medium", or "low". Required when is_genuine_bug is true.
        """
        on_verdict({
            "is_genuine_bug": is_genuine_bug,
            "reasoning": reasoning,
            "adjusted_severity": adjusted_severity,
        })
        return "Verdict received."

    return submit_verdict
