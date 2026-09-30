

import json
import os
from pathlib import Path

from .llm import estimate_tokens

MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", "100000"))
TARGET_FILE_SIZE = int(os.getenv("TARGET_FILE_SIZE", "15000"))
MAX_FILES_PER_REPO = int(os.getenv("MAX_FILES_PER_REPO", "256"))

LANG_EXT = {
    ".py": "Python",
    ".c": "C",
    ".h": "C/C++ header",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++ header",
    ".hh": "C++ header",
    ".js": "JavaScript",
    ".jsx": "JavaScript (JSX)",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript (JSX)",
    ".vue": "Vue",
    ".php": "PHP",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".go": "Go",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".cs": "C#",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".mm": "Objective-C++",
    ".scala": "Scala",
    ".pl": "Perl",
    ".pm": "Perl",
    ".sh": "Shell",
    ".bash": "Shell",
    ".lua": "Lua",
    ".dart": "Dart",
}

SKIP_DIRS = {
    "test", "tests", "testing", "spec", "__pycache__", ".venv", "venv",
    "node_modules", "vendor", "third_party", "thirdparty", "generated",
    "build", "dist", "site-packages", ".git"
}

SKIP_FILES = {
    "test", ".min."
}

def number_lines(content: str) -> str:
    """
    Adds line numbers to each line of the given content.
    """
    return "\n".join(f"{i + 1:4d} | {line}" for i, line in enumerate(content.splitlines()))


def is_auditable(relpath: str, extensions: set | dict | None = None) -> bool:
    """
    Determines if a file is auditable based on its path and extension.
    """
    parts = relpath.replace("\\", "/").lower().split("/")

    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False

    filename = parts[-1]
    if any(skip in filename for skip in SKIP_FILES):
        return False

    ext = os.path.splitext(filename)[1]
    
    # 3. Fall back to the global LANG_EXT dictionary if nothing was passed
    allowed = LANG_EXT if extensions is None else extensions
    return ext in allowed


# 4. Add the extensions parameter here as well so they can be passed through
def list_auditable_files(target_dir: Path, skip_dirs: set | None = None, extensions: set | dict | None = None) -> list[str]:
    """Walks target_dir and returns a list of relative paths."""
    
    directories_to_skip = set(SKIP_DIRS)
    if skip_dirs is not None:
        directories_to_skip.update(skip_dirs)

    found = []
    
    for root, dirs, files in os.walk(target_dir):
        # Filter out directories that we're skipping
        dirs[:] = [d for d in dirs if d not in directories_to_skip]

        for name in files:
            full = Path(root) / name
            rel = str(full.relative_to(target_dir))
            
            # Now 'extensions' is defined and safely passes None or the custom set
            if not is_auditable(rel, extensions):
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
