import os
from pathlib import Path

from .base import BaseScanner
from .code_units import extract_functions, file_preamble
from .common import (
    MODEL,
    MAX_BATCH_TOKENS,
    C_FAMILY_EXT,
    MEMORY_FINDINGS_SCHEMA,
    pick_files,
    call_json,
    append_finding,
    estimate_tokens,
)

SYSTEM_PROMPT = os.getenv("MEMORY_SYSTEM_PROMPT", (
    "You are a memory-safety auditor reviewing C/C++ functions extracted from a real codebase. "
    "You hunt for exactly these defect classes and nothing else: buffer overflows (stack and heap), "
    "out-of-bounds writes, out-of-bounds reads, use-after-free, double-free, use of uninitialized "
    "memory, and integer overflow/truncation that leads to an undersized allocation or a bad bound.\n\n"
    "WHAT TO LOOK FOR:\n"
    "- Unbounded or mis-bounded copies: strcpy, strcat, sprintf, gets, memcpy/memmove/memset where the "
    "length derives from the SOURCE rather than the DESTINATION capacity.\n"
    "- Off-by-one errors: <= vs < in loop bounds, forgetting the NUL terminator, sizeof(pointer) used "
    "where sizeof(array) was intended, strncpy leaving a non-terminated buffer.\n"
    "- Index arithmetic that is not validated against the array length, or is validated with a signed "
    "type that can go negative, or after an integer overflow/truncation.\n"
    "- Allocation size computed by multiplication or addition that can overflow before malloc/new.\n"
    "- Pointers used after free/delete, freed on more than one path, or returned/stored past the "
    "lifetime of a stack buffer.\n"
    "- Error paths and early returns that free a resource and then fall through to use it.\n\n"
    "CRITICAL RULES:\n"
    "1. The gutter shows ABSOLUTE line numbers from the original file. Report those exact numbers.\n"
    "2. The 'file' field must exactly match the file path given in the snippet header.\n"
    "3. Assume functions not shown exist and behave per their conventional contract. Do not report "
    "missing includes or unresolved symbols.\n"
    "4. If a buffer's declared size is not visible in the snippet, you may still report a defect, but "
    "you MUST set confidence to 'low'.\n"
    "5. STRICTLY IGNORE style, naming, missing docstrings, performance, and any non-memory-safety bug.\n"
    "6. Do not report a defect that is already guarded by a visible bounds check.\n"
    "Return ONLY the JSON object. If no definitive memory-safety defects exist, return an empty array."
))


# Deep scans trade throughput for attention: too many functions per request and the
# model skims instead of reasoning about each bound.
MAX_UNITS_PER_REQUEST = int(os.getenv("MAX_UNITS_PER_REQUEST", "10"))


class MemorySafetyScanner(BaseScanner):
    """Push-model scanner: structurally splits C-family files into functions and pushes each to the LLM."""

    id = "memory"
    name = "Memory Corruption Deep Scan"
    model = MODEL

    def run(self) -> None:
        files = pick_files(self.target_dir, extensions=C_FAMILY_EXT)
        print(f"  [Memory Scan] {len(files)} C-family file(s) selected")
        if not files:
            print("  [Memory Scan] No C/C++ sources found; nothing to analyze.")
            return

        for relpath in files:
            try:
                source = (self.target_dir / relpath).read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                print(f"    ! {relpath}: could not read file -> {e}")
                continue

            units = extract_functions(source)
            if not units:
                print(f"    - {relpath}: no function definitions extracted, skipping")
                continue

            preamble = file_preamble(source, units)
            chunks = self._group_units(units)
            print(f"    {relpath}: {len(units)} function(s) in {len(chunks)} request(s)")

            for chunk in chunks:
                findings = self._review_chunk(relpath, preamble, chunk)
                for finding in findings:
                    finding["file"] = relpath
                    finding["category"] = "security"
                    append_finding(self.ledger_path, finding)
                if findings:
                    names = ", ".join(u.name for u in chunk)
                    print(f"      {len(findings)} finding(s) in {names}")

    def _group_units(self, units: list) -> list:
        """Packs functions into request-sized chunks, isolating any single function that is already oversized."""
        chunks = []
        current = []
        current_tokens = 0
        budget = MAX_BATCH_TOKENS

        for unit in units:
            unit_tokens = estimate_tokens(unit.text)
            if unit_tokens > budget:
                if current:
                    chunks.append(current)
                    current, current_tokens = [], 0
                chunks.append([unit])
                continue

            if current and (current_tokens + unit_tokens > budget
                            or len(current) >= MAX_UNITS_PER_REQUEST):
                chunks.append(current)
                current, current_tokens = [], 0

            current.append(unit)
            current_tokens += unit_tokens

        if current:
            chunks.append(current)
        return chunks

    def _review_chunk(self, relpath: str, preamble: str, units: list) -> list:
        blocks = []
        for unit in units:
            numbered = "\n".join(
                f"{unit.start_line + i:4d} | {line}"
                for i, line in enumerate(unit.text.splitlines())
            )
            blocks.append(
                f"--- FUNCTION: {unit.name} (lines {unit.start_line}-{unit.end_line}) ---\n"
                f"{numbered}\n"
            )

        context = f"File-level declarations (for buffer sizes and types):\n```\n{preamble}\n```\n\n" if preamble.strip() else ""
        user = (
            f"Repo: {self.target_dir.name}\n"
            f"File: {relpath}\n\n"
            f"{context}"
            f"Analyze the following function bodies for memory-corruption defects:\n\n"
            + "\n".join(blocks)
        )

        if estimate_tokens(user) > MAX_BATCH_TOKENS:
            print(f"      ! chunk in {relpath} exceeds the token budget, skipping")
            return []

        try:
            data = call_json(self.client, self.model, SYSTEM_PROMPT, user, MEMORY_FINDINGS_SCHEMA)
        except Exception as e:
            print(f"      ! {relpath}: review failed -> {e}")
            return []

        return data.get("findings", [])
