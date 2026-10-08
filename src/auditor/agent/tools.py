import itertools
import json
import os
from pathlib import Path
from typing import Callable

from ..utils.llm import estimate_tokens
from ..utils.filesystem import number_lines
from .coverage import ReadCoverage
from ..utils.evidence import coerce_line, find_evidence, resolve_line

# Keep a wide safety margin below the 66k context window so a single huge file
# can't blow the whole conversation budget on its own.
MAX_READ_TOKENS = 15000
MAX_SEARCH_RESULTS = 100
# Fallback filter for when no extension list is given.
_BINARY_SUFFIXES = {'.png', '.jpg', '.exe', '.dll', '.so'}

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
            return f"Error reading file '{filepath}': {e}"

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
            return f"Error reading file '{filepath}': {e}"

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
            return f"Error reading directory: {e}"

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
            results = list(itertools.islice(_matches(target, query), MAX_SEARCH_RESULTS))

            if not results:
                return f"No matches found for '{query}'."
            if len(results) >= MAX_SEARCH_RESULTS:
                results.append(f"... results truncated at {MAX_SEARCH_RESULTS} matches. Use a more specific query.")
            return "\n".join(results)
        except Exception as e:
            return f"Error searching code: {e}"

    def _matches(target: Path, query: str):
        """Yields "path:line: text" for each matching line, walking files lazily."""
        for dirpath, dirs, files in os.walk(target):
            # Prune hidden directories and user-defined skip directories in-place
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in skip_set]

            for file in files:
                path = Path(dirpath) / file
                if ext_set is not None and path.suffix not in ext_set:
                    continue
                if path.suffix in _BINARY_SUFFIXES:
                    continue

                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f, start=1):
                            if query in line:
                                rel_path = path.relative_to(root).as_posix()
                                yield f"{rel_path}:{i}: {line.strip()[:300]}"
                except Exception:
                    continue

    return search_code


def make_report_issue_tool(root: Path, record: Callable[[dict], None]):
    """Builds the agent's finding-logging tool; each valid finding is passed to `record`."""
    root = Path(root).resolve()

    def report_issue(
        filepath: str,
        line: int,
        title: str,
        description: str,
        evidence: str,
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
            evidence: The exact line(s) of code containing the defect, copied verbatim from the file, without line numbers.
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

        # Check the quote now, so the agent can correct it instead of the finding being
        # silently dropped later by the pipeline's evidence check.
        try:
            source = target.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return f"Error logging issue: could not read '{filepath}': {e}"
        spans = find_evidence(source, evidence)
        if not spans:
            return (
                "Error logging issue: the evidence was not found in that file. Quote the exact "
                "line(s) of code from the file, without line numbers, then call report_issue again."
            )

        try:
            record({
                "file": rel_path,
                "line": resolve_line(coerce_line(line), spans),
                "title": title,
                "description": description,
                "evidence": evidence,
                "severity": severity,
                "confidence": confidence,
                "category": category,
                "suggested_solution": suggested_solution,
            })
            return "Issue successfully logged to the ledger."
        except Exception as e:
            return f"Error logging issue: {e}"
    return report_issue


def make_auditor_tools(root: Path, extensions: list[str] | None, skip_dirs: list[str] | None,
                       coverage: ReadCoverage, record: Callable[[dict], None]) -> list:
    """The full toolset for an exploring audit agent: browse, read, search, and report findings."""
    return [
        make_list_files_tool(root, extensions, skip_dirs),
        make_read_file_tool(root, coverage),
        make_read_file_range_tool(root, coverage),
        make_search_code_tool(root, extensions, skip_dirs),
        make_report_issue_tool(root, record),
    ]


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
