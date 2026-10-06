from pathlib import Path
from .base import BaseScanner
from ..utils.filesystem import list_auditable_files, number_lines
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
    "Return ONLY the JSON object. If no definitive localized bugs exist, return {\"findings\": []}."
)

FINDING_PROPERTIES = {
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
    "line": {
        "type": ["integer", "null"],
        "description": "1-indexed line number (from the gutter) where the defect occurs. Use null only if the defect is not tied to any specific line.",
    },
    "evidence": {
        "type": "string",
        "description": "The exact line(s) of code containing the defect, copied verbatim from the file, without the line-number gutter.",
    },
    "confidence": {
        "type": "string",
        "enum": ["high", "medium", "low"],
        "description": "Must be 'low' if the bug depends on the behavior or existence of external files/functions not visible in this snippet.",
    },
    "description": {"type": "string", "description": "Precise explanation of the defect."},
    "steps_to_reproduce": {"type": ["string", "null"]},
    "suggested_solution": {"type": "string", "description": "Concrete minimal fix (code snippet)."},
}

FINDING_REQUIRED = [
    "title", "severity", "category", "file", "line", "evidence",
    "description", "confidence", "suggested_solution",
]

def make_findings_schema(extra_properties: dict | None = None,
                         extra_required: list[str] | None = None,
                         exclude: tuple[str, ...] = ()) -> dict:
    """Builds the {"findings": [...]} response schema.

    extra_properties adds scanner-specific fields or overrides the standard ones (e.g. to give
    `description` scanner-specific guidance); exclude drops standard fields the model shouldn't fill.
    """
    properties = {k: v for k, v in {**FINDING_PROPERTIES, **(extra_properties or {})}.items() if k not in exclude}
    required = [k for k in FINDING_REQUIRED + list(extra_required or []) if k not in exclude]
    return {
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        },
        "required": ["findings"],
    }

SINGLE_FILE_FINDINGS_SCHEMA = make_findings_schema()

class SingleFileScanner(BaseScanner):
    """Reviews each auditable file in isolation with one structured-output LLM call.

    Subclasses customize the review by overriding the class attributes below.
    """
    id = "single-file"
    name = "Single File Analysis"

    SYSTEM_PROMPT: str = SINGLE_FILE_PROMPT
    SCHEMA: dict = SINGLE_FILE_FINDINGS_SCHEMA
    USER_INSTRUCTION: str = "Audit this file snippet for real, statically-justifiable bugs."
    # Fields stamped onto every finding after the model returns it (e.g. a fixed category).
    FINDING_DEFAULTS: dict = {}

    def run(self) -> None:

        # Obtain a list of all files that we can scan
        files = list_auditable_files(self.target_dir, self.extensions, self.skip_dirs)
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
                f"{self.USER_INSTRUCTION}"
            )

            # Call the LLM to generate a report over the file
            self.on_progress(f"reviewing {relpath} ({estimate_tokens(user)} tok in)")
            try:
                data = call_json(self.client, self.model, self.SYSTEM_PROMPT, user, self.SCHEMA)
            except Exception as e:
                self.on_warning(f" ! {relpath}: review failed -> {e}")
                continue

            # Write the findings to the ledger
            findings = data.get("findings", [])
            for finding in findings:
                finding.update(self.FINDING_DEFAULTS)
                finding["file"] = relpath
                self.record_finding(finding)
            if findings:
                self.on_progress(f" {relpath}: {len(findings)} finding(s)")
