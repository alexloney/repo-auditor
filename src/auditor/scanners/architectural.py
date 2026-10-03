from .base import BaseScanner
from ..agent.agent import run_agent_loop
from ..agent.tools import read_file, read_file_range, make_report_issue_tool, make_list_files_tool, make_search_code_tool

ARCHITECTURAL_SYSTEM_PROMPT = (
    "You are a meticulous principal software engineer conducting a deep integration and architectural audit of a repository. "
    "Unlike a simple linter, you must actively explore the codebase. Use your tools to navigate directories, search for usages, "
    "and trace execution flows across multiple files. "
    "CRITICAL RULES: "
    "1. Trace execution paths. When encountering external function calls, imports, or class instantiations, use the `search_code` "
    "or `read_file` tools to pull their definitions and verify that the API contracts match. "
    "2. Focus on high-value, cross-file defects: mismatched arguments, unhandled exceptions bubbling up, resource leaks across "
    "boundaries, improper state management, and architectural flaws. "
    "3. If you spot a definitive bug, you MUST use the `report_issue` tool immediately to log it, including a title, description, "
    "severity, category, and a suggested fix. "
    "4. STRICTLY IGNORE stylistic issues, missing docstrings, naming conventions, or pedantic micro-optimizations. "
    "5. When you have thoroughly traced the critical paths of the codebase, reply with 'AUDIT_COMPLETE'."
)

class ArchitecturalAgentScanner(BaseScanner):
    id = "arch"
    name = "Architectural Agentic Scan"

    def run(self) -> None:
        report_issue = make_report_issue_tool(self.ledger_path)
        list_files = make_list_files_tool(self.extensions, self.skip_dirs)
        search_code = make_search_code_tool(self.extensions, self.skip_dirs)

        run_agent_loop(
            client=self.client,
            model=self.model,
            target_dir=self.target_dir,
            ledger_path=self.ledger_path,
            system_prompt=ARCHITECTURAL_SYSTEM_PROMPT,
            initial_user_prompt="Begin the audit. Please list the files in the current directory.",
            tools=[list_files, read_file, read_file_range, search_code, report_issue],
            on_progress=self.on_progress,
            on_warning=self.on_warning,
            on_error=self.on_error,
        )
