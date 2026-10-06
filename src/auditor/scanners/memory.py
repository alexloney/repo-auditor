from .base import BaseScanner
from .single_file import make_findings_schema
from ..utils.code_units import CodeUnit, extract_functions, file_preamble
from ..utils.filesystem import list_auditable_files
from ..utils.llm import call_json, estimate_tokens

# Languages with manual memory management, where this scanner applies.
C_FAMILY_EXT = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".m", ".mm"}

# Deep scans trade throughput for attention: too many functions per request and the
# model skims instead of reasoning about each bound.
MAX_UNITS_PER_REQUEST = 10
MAX_CHUNK_TOKENS = 40000

MEMORY_SYSTEM_PROMPT = (
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
    "Return ONLY the JSON object. If no definitive memory-safety defects exist, return {\"findings\": []}."
)

MEMORY_VULN_CLASSES = [
    "buffer-overflow",
    "out-of-bounds-write",
    "out-of-bounds-read",
    "use-after-free",
    "double-free",
    "uninitialized-memory",
    "integer-overflow-leading-to-overflow",
]

MEMORY_FINDINGS_SCHEMA = make_findings_schema(
    exclude=("category",),
    extra_properties={
        "title": {"type": "string", "description": "Short, specific name of the memory-safety defect."},
        "vuln_class": {"type": "string", "enum": MEMORY_VULN_CLASSES},
        "line": {"type": ["integer", "null"], "description": "Absolute 1-indexed line number shown in the snippet gutter."},
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "Must be 'low' if the defect depends on buffer sizes or callers not visible in this snippet.",
        },
        "description": {
            "type": "string",
            "description": "Explain the allocation, the write/read bound, and why it can exceed or outlive the allocation.",
        },
    },
    extra_required=["vuln_class"],
)


class MemorySafetyScanner(BaseScanner):
    """Splits C-family files into functions and reviews small groups of them for memory corruption.

    Function-level chunks keep the model's attention on each bound, which a whole-file review
    (single-file / owasp) tends to skim. Does nothing on repositories without C-family sources.
    """
    id = "memory"
    name = "Memory Corruption Deep Scan"

    def run(self) -> None:
        # Honour --extensions: only scan C-family extensions the user hasn't excluded.
        extensions = C_FAMILY_EXT if self.extensions is None else C_FAMILY_EXT & set(self.extensions)
        files = list_auditable_files(self.target_dir, extensions, self.skip_dirs) if extensions else []
        self.on_progress(f"{len(files)} C-family file(s) selected")

        for relpath in files:
            try:
                source = (self.target_dir / relpath).read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.on_error(f" ! {relpath}: could not read file -> {e}")
                continue

            units = extract_functions(source)
            if not units:
                self.on_progress(f" - {relpath}: no function definitions found, skipping")
                continue

            preamble = file_preamble(source, units)
            chunks = self._group_units(relpath, units)
            self.on_progress(f"{relpath}: {len(units)} function(s) in {len(chunks)} request(s)")

            for chunk in chunks:
                findings = self._review_chunk(relpath, preamble, chunk)
                for finding in findings:
                    finding["file"] = relpath
                    finding["category"] = "security"
                    self.record_finding(finding)
                if findings:
                    names = ", ".join(u.name for u in chunk)
                    self.on_progress(f" {relpath}: {len(findings)} finding(s) in {names}")

    def _group_units(self, relpath: str, units: list[CodeUnit]) -> list[list[CodeUnit]]:
        """Packs functions into request-sized chunks; a function too large on its own is skipped."""
        chunks: list[list[CodeUnit]] = []
        current: list[CodeUnit] = []
        current_tokens = 0

        for unit in units:
            unit_tokens = estimate_tokens(unit.text)
            if unit_tokens > MAX_CHUNK_TOKENS:
                self.on_warning(f" ! {relpath}: {unit.name}() is too large to review ({unit_tokens} tok), skipping")
                continue

            if current and (current_tokens + unit_tokens > MAX_CHUNK_TOKENS
                            or len(current) >= MAX_UNITS_PER_REQUEST):
                chunks.append(current)
                current, current_tokens = [], 0

            current.append(unit)
            current_tokens += unit_tokens

        if current:
            chunks.append(current)
        return chunks

    def _review_chunk(self, relpath: str, preamble: str, units: list[CodeUnit]) -> list[dict]:
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

        context = (
            f"File-level declarations (for buffer sizes and types):\n```\n{preamble}\n```\n\n"
            if preamble.strip() else ""
        )
        user = (
            f"Repo: {self.target_dir.name}\n"
            f"File: {relpath}\n\n"
            f"{context}"
            f"Analyze the following function bodies for memory-corruption defects:\n\n"
            + "\n".join(blocks)
        )

        try:
            data = call_json(self.client, self.model, MEMORY_SYSTEM_PROMPT, user, MEMORY_FINDINGS_SCHEMA)
        except Exception as e:
            self.on_warning(f" ! {relpath}: review failed -> {e}")
            return []

        return data.get("findings", [])
