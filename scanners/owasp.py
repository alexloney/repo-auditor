import os
from pathlib import Path

from .base import BaseScanner
from .common import (
    MODEL,
    OWASP_FINDINGS_SCHEMA,
    pick_files,
    number_lines,
    call_json,
    append_finding,
    estimate_tokens,
)

OWASP_SYSTEM_PROMPT = os.getenv("OWASP_SYSTEM_PROMPT", (
    "You are an application security engineer performing a static review of a single source file, "
    "looking exclusively for vulnerabilities that map to the OWASP Top 10 (2021). "
    "CRITICAL RULES: "
    "1. Only report a finding if it maps to one of: Broken Access Control, Cryptographic Failures, "
    "Injection (SQL/command/template/log/etc.), Insecure Design, Security Misconfiguration, Vulnerable "
    "and Outdated Components, Identification and Authentication Failures, Software and Data Integrity "
    "Failures, Security Logging and Monitoring Failures, or Server-Side Request Forgery. "
    "2. Assume all imports and external functions exist and are correct. DO NOT report ImportErrors. "
    "3. STRICTLY IGNORE spelling typos, stylistic issues, missing docstrings, or naming conventions. "
    "4. Do not report generic logic bugs, performance issues, or micro-optimizations unless they "
    "directly create a security vulnerability. "
    "5. Assume third-party/library code itself is correct; only flag how THIS code calls it insecurely. "
    "Return ONLY the JSON object. If no definitive vulnerabilities exist, return an empty array."
))


class OwaspScanner(BaseScanner):
    """Reviews each eligible file in isolation for OWASP Top 10 (2021) vulnerabilities."""

    id = "owasp"
    name = "OWASP Top 10 Scan"
    model = MODEL

    def run(self) -> None:
        files = pick_files(self.target_dir)
        print(f"  [OWASP Scan] {len(files)} audit-eligible file(s) selected")

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
                f"Audit this file snippet for real, statically-justifiable OWASP Top 10 vulnerabilities."
            )

            print(f"    reviewing {relpath} ({estimate_tokens(user)} tok in)")
            try:
                data = call_json(self.client, self.model, OWASP_SYSTEM_PROMPT, user, OWASP_FINDINGS_SCHEMA)
            except Exception as e:
                print(f"    ! {relpath}: review failed -> {e}")
                continue

            findings = data.get("findings", [])
            for finding in findings:
                finding["file"] = relpath
                # Evaluator dedupe/reporting groups by "category"; keep the OWASP mapping alongside it.
                finding["category"] = "security"
                append_finding(self.ledger_path, finding)
            if findings:
                print(f"    {relpath}: {len(findings)} finding(s)")
