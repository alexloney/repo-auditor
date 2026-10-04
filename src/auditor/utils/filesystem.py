import fnmatch
import json
import os
from pathlib import Path

MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", "100000"))

# Glob patterns (matched against the lowercased filename) for test and minified files.
# Patterns rather than a substring match, so files like "latest.py" or "contest.c" are kept.
SKIP_FILE_PATTERNS = (
    "test_*", "*_test.*", "*_tests.*", "*.test.*", "*.spec.*", "*.min.*",
)

def number_lines(content: str) -> str:
    """
    Adds line numbers to each line of the given content.
    """
    return "\n".join(f"{i + 1:4d} | {line}" for i, line in enumerate(content.splitlines()))


def is_auditable(relpath: str, extensions: set | dict | None = None, skip_dirs: set | dict | None = None) -> bool:
    """
    Determines if a file is auditable based on its path and extension.
    """
    parts = relpath.replace("\\", "/").lower().split("/")

    if skip_dirs is not None and any(p in skip_dirs for p in parts[:-1]):
        return False

    filename = parts[-1]
    if any(fnmatch.fnmatchcase(filename, pattern) for pattern in SKIP_FILE_PATTERNS):
        return False

    ext = os.path.splitext(filename)[1]

    # If no specific extensions are provided, consider all files auditable
    if extensions is None:
        return True
    
    return ext in extensions


def list_auditable_files(target_dir: Path, extensions: set | dict | None = None, skip_dirs: set | None = None) -> list[str]:
    """Walks target_dir and returns a list of relative paths."""
    
    directories_to_skip = set()
    if skip_dirs is not None:
        directories_to_skip.update(skip_dirs)

    found = []
    
    for root, dirs, files in os.walk(target_dir):
        # Filter out directories that we're skipping
        dirs[:] = [d for d in dirs if d not in directories_to_skip]

        for name in files:
            full = Path(root) / name
            # Always use forward slashes so findings from different scanners (and OSes)
            # share the same path and can be deduplicated against each other.
            rel = full.relative_to(target_dir).as_posix()

            # extensions=None means every file extension is auditable
            if not is_auditable(rel, extensions, skip_dirs):
                continue

            try:
                size = full.stat().st_size
                if size > MAX_FILE_SIZE_BYTES:
                    continue
            except OSError:
                continue

            found.append(rel)

    return found

def append_finding(ledger_path: Path, finding: dict) -> None:
    """
    Appends a finding to the ledger file.
    """
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(finding) + "\n")
