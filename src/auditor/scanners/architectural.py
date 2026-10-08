from .base import BaseScanner
from ..agent.agent import run_agent_loop
from ..agent.coverage import ReadCoverage
from ..agent.tools import make_auditor_tools

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
        coverage = ReadCoverage()
        run_agent_loop(
            client=self.client,
            model=self.model,
            system_prompt=ARCHITECTURAL_SYSTEM_PROMPT,
            initial_user_prompt="Begin the audit. Please list the files in the repository root ('.').",
            tools=make_auditor_tools(self.target_dir, self.extensions, self.skip_dirs, coverage, self.record_finding),
            max_turns=self.max_turns,
            coverage=coverage,
            on_progress=self.on_progress,
            on_warning=self.on_warning,
            on_error=self.on_error,
        )
