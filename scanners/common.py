"""Shared helpers for the structured-output scanners (single_file.py, batch.py).

Ported from the older monolithic llm-audit/audit.py, which used direct
schema-constrained LLM completions instead of an agentic tool-calling loop.
"""
import json
import os
import time
from pathlib import Path

MODEL = os.getenv("MODEL", "qwen-coder-64k:latest")
MAX_CONTEXT = int(os.getenv("MAX_CONTEXT", "66000"))
MAX_FILES_PER_REPO = int(os.getenv("MAX_FILES_PER_REPO", "60"))
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", "100000"))
TARGET_FILE_SIZE = int(os.getenv("TARGET_FILE_SIZE", "15000"))
MAX_FILES_PER_BATCH = int(os.getenv("MAX_FILES_PER_BATCH", "4"))
MAX_BATCH_TOKENS = int(os.getenv("MAX_BATCH_TOKENS", "45000"))

LANG_EXT = {
    ".py": "Python",
    ".c": "C",
    ".h": "C/C++ header",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".hpp": "C++ header",
    ".hh": "C++ header",
}

# Directories to skip entirely.
SKIP_DIRS = {
    "test", "tests", "testing", "spec", "__pycache__", ".venv", "venv",
    "node_modules", "vendor", "third_party", "thirdparty", "generated",
    "build", "dist", "site-packages",
}

FINDINGS_SCHEMA = {
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

OWASP_CATEGORIES = [
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery",
]

OWASP_FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short, specific name of the vulnerability."},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "owasp_category": {"type": "string", "enum": OWASP_CATEGORIES},
                    "file": {"type": "string"},
                    "line": {"type": ["integer", "null"], "description": "1-indexed line from the provided snippet."},
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": "Must be 'low' if exploitability depends on external files/config not visible in this snippet.",
                    },
                    "description": {"type": "string", "description": "Precise explanation of the vulnerability and its impact."},
                    "steps_to_reproduce": {"type": ["string", "null"]},
                    "suggested_solution": {"type": "string", "description": "Concrete minimal fix (code snippet)."},
                },
                "required": [
                    "title", "severity", "owasp_category", "file",
                    "description", "confidence", "suggested_solution",
                ],
            },
        },
    },
    "required": ["findings"],
}

BATCH_PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "batches": {
            "type": "array",
            "items": {
                "type": "array",
                "items": {"type": "string", "description": "Exact file path as provided"},
                "description": f"Group of up to {MAX_FILES_PER_BATCH} related files.",
            },
        },
    },
    "required": ["batches"],
}


def estimate_tokens(text: str) -> int:
    try:
        import tiktoken
        enc = tiktoken.get_encoding("cl100k_base")
        return len(enc.encode(text))
    except Exception:
        return max(1, len(text) // 4)


def is_auditable(relpath: str) -> bool:
    parts = relpath.replace("\\", "/").lower().split("/")

    if any(p in SKIP_DIRS for p in parts[:-1]):
        return False

    filename = parts[-1]
    if "test" in filename or "min" in filename or ".min." in filename:
        return False

    ext = os.path.splitext(filename)[1]
    return ext in LANG_EXT


def pick_files(target_dir: Path) -> list:
    """Walks target_dir and returns a size-bounded, size-prioritized list of relative paths."""
    found = []
    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d != ".git"]

        for name in files:
            full = Path(root) / name
            rel = str(full.relative_to(target_dir))
            if not is_auditable(rel):
                continue

            try:
                size = full.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_SIZE_BYTES:
                continue

            found.append((size, rel))

    # Sort by proximity to an ideal file size to prioritize self-contained logic
    found.sort(key=lambda t: abs(t[0] - TARGET_FILE_SIZE))
    return [rel for _size, rel in found[:MAX_FILES_PER_REPO]]


def number_lines(content: str) -> str:
    return "\n".join(f"{i + 1:4d} | {line}" for i, line in enumerate(content.splitlines()))


def call_json(client, model: str, system: str, user: str, schema: dict, retries: int = 3) -> dict:
    """Calls the LLM with a JSON schema response format, retrying on transient failures."""
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            resp = client.chat(
                model=model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                format=schema,
                options={"temperature": 0.0, "num_ctx": MAX_CONTEXT},
            )
            return json.loads(resp.message.content)
        except Exception as e:
            last_err = e
            print(f"    call_json attempt {attempt}/{retries} failed: {e}")
            time.sleep(2 * attempt)
    raise RuntimeError(f"call_json failed after {retries} tries: {last_err}")


def append_finding(ledger_path: Path, finding: dict) -> None:
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(finding) + "\n")
