import os
from pathlib import Path
from .base import BaseScanner
from ..utils.filesystem import list_auditable_files, number_lines, append_finding
from ..utils.llm import call_json, estimate_tokens

SINGLE_FILE_PROMPT = (
    "You are a meticulous senior software engineer auditing a single isolated file to find "
    "definitive bugs for Pull Requests. "
    "CRITICAL RULES: "
    "1. Assume all imports and external functions exist and are correct. DO NOT report ImportErrors. "
    "2. STRICTLY IGNORE spelling typos in filenames, paths, or import statements. "
    "3. Focus exclusively on microscopic, localized defects: regex parsing errors, malformed strings, "
    "off-by-one boundary conditions, and localized math/logic flaws. "
    "4. STRICTLY IGNORE stylistic issues, missing docstrings, or naming conventions. "
    "Return ONLY the JSON object. If no definitive localized bugs exist, return an empty array."
)

SINGLE_FILE_FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, specific name of the bug."},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "category": {
                        "type": "string",
                        "enum": [
                            "bug", "security", "resource-leak", "race-condition",
                            "performance", "correctness", "api-misuse", "other",
                        ],
                    },
                    "file": {"type": "string"},
                    "line": {"type": ["integer", "null"], "description": "1-indexed line from the provided snippet."},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Must be 'low' if the bug depends on the behavior or existence of external files/functions not visible in this snippet.",
                    },
                    "description": {"type": "string", "description": "Precise explanation of the defect."},
                    "steps_to_reproduce": {"type": ["string", "null"]},
                    "suggested_solution": {"type": "string", "description": "Concrete minimal fix (code snippet)."},
                },
                "required": [
                    "title", "severity", "category", "file",
                    "description", "confidence", "suggested_solution",
                ],
            },
        },
    },
    "required": ["findings"],
}

class SingleFileScanner(BaseScanner):
    id = "single-file"
    name = "Single File Analysis"

    def run(self) -> None:

        # Obtain a list of all files that we can scan
        files = list_auditable_files(self.target_dir, self.skip_dirs, self.extensions)
        self.on_progress(f"{len(files)} audit-eligible file(s) selected")

        # Loop through all files that we can scan
        for relpath in files:

            # Obtain the full path for the file, then read the file
            # contents.
            full = self.target_dir / relpath
            try:
                content = full.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.on_error(f" ! {relpath}: could not read file -> {e}")
                continue

            # Build our user prompt for this file, add line numbers
            # to the file that's being scanned.
            user = (
                f"Repo: {self.target_dir.name}\n"
                f"File: {relpath}\n\n"
                f"```{Path(relpath).suffix.lstrip('.')}\n{number_lines(content)}\n```\n\n"
                f"Audit this file snippet for real, statically-justifiable bugs."
            )

            # Call the LLM to generate a report over the file
            self.on_progress(f"reviewing {relpath} ({estimate_tokens(user)} tok in)")
            try:
                data = call_json(self.client, self.model, SINGLE_FILE_PROMPT, user, SINGLE_FILE_FINDINGS_SCHEMA)
            except Exception as e:
                self.on_warning(f" ! {relpath}: review failed -> {e}")
                continue

            # Write the findings to the ledger
            findings = data.get("findings", [])
            for finding in findings:
                finding["file"] = relpath
                append_finding(self.ledger_path, finding)
            if findings:
                self.on_progress(f" {relpath}: {len(findings)} finding(s)")
