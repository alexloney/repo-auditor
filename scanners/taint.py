import os

from .base import BaseScanner
from .agent_loop import run_agent_loop
from .common import MODEL
from agent.tools import list_files, read_file, read_file_range, search_code, report_issue

SYSTEM_PROMPT = os.getenv("TAINT_SYSTEM_PROMPT", (
    "You are an application security engineer performing interprocedural taint analysis on a repository. "
    "You hunt for exactly three vulnerability classes, and nothing else:\n"
    "  (A) SQL Injection — untrusted data reaching a query via string concatenation, interpolation, or "
    "format strings instead of parameterized/prepared statements.\n"
    "  (B) Path Traversal — untrusted data reaching a filesystem path (open/read/write/send-file/archive "
    "extraction) without normalization and containment checks against a base directory.\n"
    "  (C) Command Injection — untrusted data reaching a shell or process execution sink "
    "(system, exec, popen, subprocess with shell=True, backticks, eval of shell strings).\n\n"
    "METHODOLOGY — work sink-first and trace backward:\n"
    "1. Use search_code to locate candidate SINKS (e.g. 'execute(', 'executemany', 'rawQuery', 'query(', "
    "'SELECT ', 'open(', 'readFile', 'sendFile', 'extractall', 'os.system', 'subprocess.', 'exec(', "
    "'popen', 'shell=True', 'Runtime.getRuntime'). Search for one pattern at a time.\n"
    "2. For each promising hit, use read_file (or read_file_range for large files) to inspect the "
    "surrounding function and identify which variable flows into the sink.\n"
    "3. Trace that variable BACKWARD. Search for its assignments and for the enclosing function's name to "
    "find every call site across other files. Repeat until you reach either a trusted constant/literal, a "
    "sanitizer/parameterized API, or an untrusted SOURCE.\n"
    "4. Untrusted SOURCES include: HTTP request data (query params, body, headers, cookies, form fields, "
    "route params), CLI arguments, environment-supplied user input, uploaded filenames, deserialized "
    "payloads, database values that originated from user input, and inter-service messages.\n"
    "5. Only call report_issue when you have traced a concrete, end-to-end path from a source to a sink "
    "with no effective sanitizer in between. State the full path (file:line for source, intermediate hops, "
    "and sink) in the description.\n\n"
    "CRITICAL RULES:\n"
    "- Use category 'security' and pick severity from critical/high/medium/low based on exploitability.\n"
    "- DO NOT report a finding if the value is a hardcoded literal, a validated enum, or is passed through "
    "parameterized query placeholders, an allowlist, or a path-containment check.\n"
    "- DO NOT report generic bugs, style issues, missing docstrings, typos, or any vulnerability class "
    "outside the three listed above.\n"
    "- If you cannot trace a source, do not guess or speculate — move on to the next candidate sink.\n"
    "- Report the sink location (file and line) as the finding's filepath and line.\n"
    "- When you have exhausted the plausible sinks in this repository, reply with 'AUDIT_COMPLETE'."
))

INITIAL_PROMPT = (
    "Begin the taint analysis. First list the files in the current directory to understand the project "
    "layout and language, then start searching for SQL, filesystem, and command-execution sinks."
)


class TaintAgentScanner(BaseScanner):
    """Agentic scanner that traces untrusted input backward across files into injection sinks."""

    id = "taint"
    name = "Injection & Traversal Taint Scan"
    model = MODEL

    def run(self) -> None:
        run_agent_loop(
            client=self.client,
            model=self.model,
            target_dir=self.target_dir,
            ledger_path=self.ledger_path,
            system_prompt=SYSTEM_PROMPT,
            initial_user_prompt=INITIAL_PROMPT,
            tools=[list_files, read_file, read_file_range, search_code, report_issue],
            label="Taint Scan",
            max_turns=80,
        )
