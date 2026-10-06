import posixpath
import re
from collections import deque
from pathlib import Path

from .base import BaseScanner
from .single_file import SINGLE_FILE_FINDINGS_SCHEMA
from ..utils.filesystem import list_auditable_files, number_lines
from ..utils.llm import call_json, estimate_tokens

MAX_FILES_PER_BATCH = 4
MAX_BATCH_TOKENS = 40000

BATCH_SYSTEM_PROMPT = (
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
    "network sessions), unhandled None/null dereferences, mismatched arguments or return values between "
    "the files shown, and API misuse. "
    "5. STRICTLY IGNORE stylistic issues, missing docstrings, naming conventions, or micro-optimizations. "
    "6. BE EXHAUSTIVE. You must systematically evaluate EVERY file provided in the batch. "
    "Return ONLY the JSON object. Ensure the 'file' field in each finding exactly matches the filename "
    "provided in the file headers. If no definitive bugs exist, return {\"findings\": []}."
)

# Statement prefixes that pull in other code, across the supported languages.
_IMPORT_PREFIXES = (
    "import ", "from ", "#include", "# include", "using ", "use ", "require", "mod ",
    "@import", "include ", "include_once", "export ",
)
# Generic stems (package entry points) are identified by their directory name instead.
_GENERIC_STEMS = {"__init__", "index", "mod", "main", "lib"}


def _import_tokens(text: str) -> set[str]:
    """Identifier-ish words appearing on the file's import/include/require lines."""
    tokens: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(_IMPORT_PREFIXES) or "require(" in stripped or "import(" in stripped:
            tokens.update(re.findall(r"[\w-]+", stripped))
    return tokens


def _module_key(relpath: str) -> str:
    """The name other files would most likely use to import relpath."""
    stem = posixpath.splitext(posixpath.basename(relpath))[0]
    if stem in _GENERIC_STEMS:
        return posixpath.basename(posixpath.dirname(relpath)) or stem
    return stem


def build_import_graph(contents: dict[str, str]) -> dict[str, set[str]]:
    """Undirected graph linking each file to the repo files its import lines refer to."""
    by_key: dict[str, list[str]] = {}
    for relpath in contents:
        by_key.setdefault(_module_key(relpath), []).append(relpath)

    edges: dict[str, set[str]] = {relpath: set() for relpath in contents}
    for relpath, text in contents.items():
        for token in _import_tokens(text) & by_key.keys():
            for other in by_key[token]:
                if other != relpath:
                    edges[relpath].add(other)
                    edges[other].add(relpath)
    return edges


def plan_batches(files: list[str], edges: dict[str, set[str]], sizes: dict[str, int],
                 max_files: int = MAX_FILES_PER_BATCH, max_tokens: int = MAX_BATCH_TOKENS) -> list[list[str]]:
    """Groups related files into batches; every file lands in exactly one batch.

    Related files (via the import graph) are grouped breadth-first from the most-connected
    files outward. Files with no related file that fits are packed together by directory.
    """
    assigned: set[str] = set()
    batches: list[list[str]] = []

    for seed in sorted(files, key=lambda f: (-len(edges[f]), f)):
        if seed in assigned or not edges[seed]:
            continue
        batch, tokens = [seed], sizes[seed]
        assigned.add(seed)
        queue = deque(sorted(edges[seed]))
        while queue and len(batch) < max_files:
            candidate = queue.popleft()
            if candidate in assigned or tokens + sizes[candidate] > max_tokens:
                continue
            batch.append(candidate)
            assigned.add(candidate)
            tokens += sizes[candidate]
            queue.extend(sorted(edges[candidate] - assigned))
        if len(batch) > 1:
            batches.append(batch)
        else:
            assigned.discard(seed)  # nothing related fit; pack it with the leftovers

    # Leftovers are packed per directory: files that sit together are the next-best guess
    # at related code, and mixing directories would just add unrelated context.
    by_dir: dict[str, list[str]] = {}
    for relpath in sorted(f for f in files if f not in assigned):
        by_dir.setdefault(posixpath.dirname(relpath), []).append(relpath)

    for dir_files in by_dir.values():
        current: list[str] = []
        tokens = 0
        for relpath in dir_files:
            if current and (len(current) >= max_files or tokens + sizes[relpath] > max_tokens):
                batches.append(current)
                current, tokens = [], 0
            current.append(relpath)
            tokens += sizes[relpath]
        if current:
            batches.append(current)

    return batches


def _normalize(path) -> str:
    return str(path or "").replace("\\", "/").removeprefix("./")


class BatchScanner(BaseScanner):
    """Reviews groups of related files together so the model can check contracts between them.

    Sits between `single-file` (no cross-file context) and `arch` (cross-file, but the agent
    chooses what to read, so coverage isn't guaranteed): every file is reviewed, alongside
    the files it imports or is imported by.
    """
    id = "batch"
    name = "Batched Context Analysis"

    def run(self) -> None:
        files = list_auditable_files(self.target_dir, self.extensions, self.skip_dirs)
        self.on_progress(f"{len(files)} audit-eligible file(s) selected")

        contents: dict[str, str] = {}
        blocks: dict[str, str] = {}
        sizes: dict[str, int] = {}
        for relpath in files:
            try:
                text = (self.target_dir / relpath).read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                self.on_error(f" ! {relpath}: could not read file -> {e}")
                continue
            if not text.strip():
                continue  # e.g. empty __init__.py: nothing to review, and it would waste a batch slot
            block = (
                f"--- START FILE: {relpath} ---\n"
                f"```{Path(relpath).suffix.lstrip('.')}\n{number_lines(text)}\n```\n"
                f"--- END FILE: {relpath} ---\n"
            )
            size = estimate_tokens(block)
            if size > MAX_BATCH_TOKENS:
                self.on_warning(f" ! {relpath}: too large to batch ({size} tok), skipping")
                continue
            contents[relpath], blocks[relpath], sizes[relpath] = text, block, size

        if not contents:
            return

        batch_files = list(contents)
        batches = plan_batches(batch_files, build_import_graph(contents), sizes)
        self.on_progress(f"{len(batches)} batch(es) planned")

        for idx, batch in enumerate(batches, start=1):
            user = (
                f"Repo: {self.target_dir.name}\n\n"
                f"Audit the following files for real, statically-justifiable bugs:\n\n"
                + "\n".join(blocks[relpath] for relpath in batch)
            )
            self.on_progress(f"reviewing batch {idx}/{len(batches)}: {', '.join(batch)} ({estimate_tokens(user)} tok in)")
            try:
                data = call_json(self.client, self.model, BATCH_SYSTEM_PROMPT, user, SINGLE_FILE_FINDINGS_SCHEMA)
            except Exception as e:
                self.on_warning(f" ! batch {idx} failed -> {e}")
                continue

            batch_set = set(batch)
            kept = 0
            for finding in data.get("findings", []):
                # The model must attribute each finding to one of the files it was actually shown.
                relpath = _normalize(finding.get("file"))
                if relpath not in batch_set:
                    self.on_warning(f" ! Dropping finding with unrecognized file '{finding.get('file')}'")
                    continue
                finding["file"] = relpath
                self.record_finding(finding)
                kept += 1
            if kept:
                self.on_progress(f" batch {idx}: {kept} finding(s)")
