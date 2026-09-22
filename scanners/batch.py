import os
from pathlib import Path

from .base import BaseScanner
from .common import (
    MODEL,
    MAX_FILES_PER_BATCH,
    MAX_BATCH_TOKENS,
    FINDINGS_SCHEMA,
    BATCH_PLAN_SCHEMA,
    pick_files,
    number_lines,
    call_json,
    append_finding,
    estimate_tokens,
)

PLANNER_SYSTEM_PROMPT = os.getenv("PLANNER_SYSTEM_PROMPT", (
    "You are an expert software architect planning a code review. "
    "I will provide a list of source files from a repository. "
    "Your task is to group these files into logical batches for static analysis. "
    "Group files that likely interact, share state, or import each other (e.g., group models "
    "together, or group a parser with its data structures). "
    "CRITICAL RULES: "
    f"1. A single batch MUST NOT contain more than {MAX_FILES_PER_BATCH} files. "
    "2. EVERY file in the provided list MUST be assigned to exactly one batch. "
    "3. Use the exact file paths provided. Do not hallucinate files. "
    "Return ONLY the JSON object."
))

BATCH_FILE_PROMPT = os.getenv("BATCH_FILE_PROMPT", (
    "You are a meticulous senior software engineer auditing a batch of codebase files to find "
    "definitive bugs for Pull Requests. "
    "You are doing STATIC analysis. You have access to multiple files simultaneously; use them to "
    "verify cross-module imports and function signatures. "
    "CRITICAL RULES: "
    "1. Assume any modules or functions not included in this batch exist elsewhere and are correct. "
    "DO NOT report ImportErrors for missing external files. "
    "2. STRICTLY IGNORE spelling typos in filenames, paths, or import statements. "
    "3. Evaluate standard libraries and popular third-party packages for API misuse or unhandled edge cases. "
    "4. Focus on definitive defects: logic errors, resource leaks (including unclosed files, sockets, and "
    "network sessions), unhandled None/null dereferences, and API misuse. "
    "5. STRICTLY IGNORE stylistic issues, missing docstrings, naming conventions, or micro-optimizations. "
    "6. BE EXHAUSTIVE. You must systematically evaluate EVERY file provided in the batch. "
    "Return ONLY the JSON object. Ensure the 'file' field in each finding exactly matches the filename "
    "provided in the prompt headers."
))


class BatchScanner(BaseScanner):
    """Clusters related files with an LLM planner, then audits each cluster together."""

    id = "batch"
    name = "Batched Context Analysis"
    model = MODEL

    def run(self) -> None:
        files = pick_files(self.target_dir)
        print(f"  [Batch Scan] {len(files)} audit-eligible file(s) selected")
        if not files:
            return

        batches = self._plan_batches(files)
        print(f"  [Batch Scan] Generated {len(batches)} strategic batch(es)")

        for idx, batch in enumerate(batches):
            batch_set = set(batch)
            combined = []
            for relpath in batch:
                try:
                    content = (self.target_dir / relpath).read_text(encoding="utf-8", errors="replace")
                except OSError as e:
                    print(f"    ! {relpath}: could not read file -> {e}")
                    continue
                ext = Path(relpath).suffix.lstrip('.')
                combined.append(
                    f"--- START FILE: {relpath} ---\n"
                    f"```{ext}\n{number_lines(content)}\n```\n"
                    f"--- END FILE: {relpath} ---\n"
                )

            if not combined:
                continue

            user = (
                f"Repo: {self.target_dir.name}\n\n"
                f"Audit the following files for real, statically-justifiable bugs:\n\n"
                + "\n".join(combined)
            )

            total_tokens = estimate_tokens(user)
            if total_tokens > MAX_BATCH_TOKENS:
                print(f"    ! Batch {idx + 1} exceeds safe token limit ({total_tokens}). Skipping.")
                continue

            print(f"    reviewing batch {idx + 1}/{len(batches)} of {len(batch)} file(s) ({total_tokens} tok in)")
            try:
                data = call_json(self.client, self.model, BATCH_FILE_PROMPT, user, FINDINGS_SCHEMA)
            except Exception as e:
                print(f"    ! Batch {idx + 1} failed -> {e}")
                continue

            kept = 0
            for finding in data.get("findings", []):
                # The model must attribute each finding to one of the files we actually sent it.
                if finding.get("file") not in batch_set:
                    print(f"    ! Dropping finding with unrecognized file '{finding.get('file')}'")
                    continue
                append_finding(self.ledger_path, finding)
                kept += 1
            if kept:
                print(f"    batch {idx + 1}: {kept} finding(s)")

    def _plan_batches(self, files: list) -> list:
        """Asks the LLM to cluster files based on imports and naming conventions."""
        file_summaries = []
        for relpath in files:
            full = self.target_dir / relpath
            imports = []
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    for _ in range(30):  # Check the top of the file for imports
                        line = f.readline()
                        if not line:
                            break
                        line = line.strip()
                        if line.startswith("import ") or line.startswith("from ") or line.startswith("#include"):
                            imports.append(line)
            except OSError:
                pass

            summary = f"- {relpath}"
            if imports:
                summary += f"  (Imports: {', '.join(imports[:3])}...)"
            file_summaries.append(summary)

        user = "Repository files to group:\n" + "\n".join(file_summaries)
        print(f"  [Batch Scan] Asking LLM to group {len(files)} file(s) logically...")

        try:
            data = call_json(self.client, self.model, PLANNER_SYSTEM_PROMPT, user, BATCH_PLAN_SCHEMA)
            llm_batches = data.get("batches", [])
        except Exception as e:
            print(f"    ! Planner failed, falling back to sequential batching: {e}")
            llm_batches = []

        # LLMs occasionally hallucinate or drop items; reconcile against the real file list.
        valid_batches = []
        seen = set()
        valid_file_set = set(files)

        for batch in llm_batches:
            clean_batch = []
            for file in batch:
                if file in valid_file_set and file not in seen:
                    clean_batch.append(file)
                    seen.add(file)
            if clean_batch:
                valid_batches.append(clean_batch)

        # Sweep up any files the LLM forgot to include
        orphans = [f for f in files if f not in seen]
        if orphans:
            print(f"    [Batch Scan] Recovered {len(orphans)} orphaned file(s).")
            for i in range(0, len(orphans), MAX_FILES_PER_BATCH):
                valid_batches.append(orphans[i:i + MAX_FILES_PER_BATCH])

        return valid_batches
