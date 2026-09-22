import os
from pathlib import Path

from .base import BaseScanner
from .common import (
    MODEL,
    FINDINGS_SCHEMA,
    pick_files,
    number_lines,
    call_json,
    append_finding,
    estimate_tokens,
)

SINGLE_FILE_PROMPT = os.getenv("SINGLE_FILE_PROMPT", (
    "You are a meticulous senior software engineer auditing a single isolated file to find "
    "definitive bugs for Pull Requests. "
    "CRITICAL RULES: "
    "1. Assume all imports and external functions exist and are correct. DO NOT report ImportErrors. "
    "2. STRICTLY IGNORE spelling typos in filenames, paths, or import statements. "
    "3. Focus exclusively on microscopic, localized defects: regex parsing errors, malformed strings, "
    "off-by-one boundary conditions, and localized math/logic flaws. "
    "4. STRICTLY IGNORE stylistic issues, missing docstrings, or naming conventions. "
    "Return ONLY the JSON object. If no definitive localized bugs exist, return an empty array."
))


class SingleFileScanner(BaseScanner):
    """Reviews each eligible file in isolation with a schema-constrained LLM call."""

    id = "single-file"
    name = "Single File Analysis"
    model = MODEL

    def run(self) -> None:
        files = pick_files(self.target_dir)
        print(f"  [Single File Scan] {len(files)} audit-eligible file(s) selected")

        for relpath in files:
            full = self.target_dir / relpath
            try:
                content = full.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                print(f"    ! {relpath}: could not read file -> {e}")
                continue

            user = (
                f"Repo: {self.target_dir.name}\n"
                f"File: {relpath}\n\n"
                f"```{Path(relpath).suffix.lstrip('.')}\n{number_lines(content)}\n```\n\n"
                f"Audit this file snippet for real, statically-justifiable bugs."
            )

            print(f"    reviewing {relpath} ({estimate_tokens(user)} tok in)")
            try:
                data = call_json(self.client, self.model, SINGLE_FILE_PROMPT, user, FINDINGS_SCHEMA)
            except Exception as e:
                print(f"      ! {relpath}: review failed -> {e}")
                continue

            findings = data.get("findings", [])
            for finding in findings:
                finding["file"] = relpath
                append_finding(self.ledger_path, finding)
            if findings:
                print(f"      {relpath}: {len(findings)} finding(s)")
