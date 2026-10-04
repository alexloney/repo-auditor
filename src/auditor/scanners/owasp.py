from .single_file import SingleFileScanner, make_findings_schema

OWASP_SYSTEM_PROMPT = (
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
    "Return ONLY the JSON object. If no definitive vulnerabilities exist, return {\"findings\": []}."
)

OWASP_CATEGORIES = [
    "A01:2021 Broken Access Control",
    "A02:2021 Cryptographic Failures",
    "A03:2021 Injection",
    "A04:2021 Insecure Design",
    "A05:2021 Security Misconfiguration",
    "A06:2021 Vulnerable and Outdated Components",
    "A07:2021 Identification and Authentication Failures",
    "A08:2021 Software and Data Integrity Failures",
    "A09:2021 Security Logging and Monitoring Failures",
    "A10:2021 Server-Side Request Forgery",
]

class OwaspScanner(SingleFileScanner):
    id = "owasp"
    name = "OWASP Top 10 Analysis"

    SYSTEM_PROMPT = OWASP_SYSTEM_PROMPT
    USER_INSTRUCTION = "Audit this file snippet for real, statically-justifiable OWASP Top 10 vulnerabilities."
    SCHEMA = make_findings_schema(
        extra_properties={
            "owasp_category": {"type": "string", "enum": OWASP_CATEGORIES},
            "vuln_class": {
                "type": "string",
                "description": "Specific vulnerability class, e.g. 'SQL injection' or 'CWE-79: Cross-site Scripting'.",
            },
        },
        extra_required=["owasp_category", "vuln_class"],
    )
