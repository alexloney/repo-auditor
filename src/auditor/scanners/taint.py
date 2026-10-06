from .base import BaseScanner
from ..agent.agent import run_agent_loop
from ..agent.coverage import ReadCoverage
from ..agent.tools import (
    make_read_file_tool, make_read_file_range_tool, make_report_issue_tool,
    make_list_files_tool, make_search_code_tool,
)

TAINT_SYSTEM_PROMPT = (
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
)

TAINT_INITIAL_PROMPT = (
    "Begin the taint analysis. First list the files in the repository root ('.') to understand the "
    "project layout and language, then start searching for SQL, filesystem, and command-execution sinks."
)


class TaintAgentScanner(BaseScanner):
    """Agent that traces untrusted input backward across files into injection sinks.

    Complements the per-file `owasp` scanner, which can't see a source that lives in a
    different file from its sink.
    """
    id = "taint"
    name = "Injection & Traversal Taint Scan"

    def run(self) -> None:
        root = self.target_dir
        coverage = ReadCoverage()
        tools = [
            make_list_files_tool(root, self.extensions, self.skip_dirs),
            make_read_file_tool(root, coverage),
            make_read_file_range_tool(root, coverage),
            make_search_code_tool(root, self.extensions, self.skip_dirs),
            make_report_issue_tool(root, self.record_finding),
        ]

        run_agent_loop(
            client=self.client,
            model=self.model,
            system_prompt=TAINT_SYSTEM_PROMPT,
            initial_user_prompt=TAINT_INITIAL_PROMPT,
            tools=tools,
            max_turns=self.max_turns,
            coverage=coverage,
            on_progress=self.on_progress,
            on_warning=self.on_warning,
            on_error=self.on_error,
        )
