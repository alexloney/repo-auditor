from .base import BaseScanner
from .agent_loop import run_agent_loop
from .common import MODEL
from agent.tools import list_files, read_file, read_file_range, search_code, report_issue

# Updated to explicitly instruct the use of the report_issue tool
SYSTEM_PROMPT = ("You are a meticulous senior software engineer exploring and auditing a repository. "
                 "Use your tools to list directories, search for text, and read source files. "
                 "CRITICAL RULES: "
                 "1. If you spot a definitive bug, you MUST use the report_issue tool immediately to log it, "
                 "including a title, description, severity, category, and a suggested fix. "
                 "2. Assume all imports and external functions exist and are correct. DO NOT report ImportErrors. "
                 "3. STRICTLY IGNORE spelling typos in filenames, paths, or import statements. "
                 "4. Focus exclusively on microscopic, localized defects: regex parsing errors, malformed strings, off-by-one boundary conditions, and localized math/logic flaws. "
                 "5. STRICTLY IGNORE stylistic issues, missing docstrings, or naming conventions. "
                 "6. When you are finished exploring the codebase, reply with 'AUDIT_COMPLETE'.")


class ShallowAgentScanner(BaseScanner):
    id = "shallow"
    name = "Shallow Agentic Scan"
    model = MODEL

    def run(self) -> None:
        run_agent_loop(
            client=self.client,
            model=self.model,
            target_dir=self.target_dir,
            ledger_path=self.ledger_path,
            system_prompt=SYSTEM_PROMPT,
            initial_user_prompt="Begin the audit. Please list the files in the current directory.",
            tools=[list_files, read_file, read_file_range, search_code, report_issue],
            label="Shallow Scan",
        )
