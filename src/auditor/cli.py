import argparse
import logging
import sys
from pathlib import Path
from auditor.pipeline import execute_audit, get_available_scanners, filter_scanners, DEFAULT_REQUEST_TIMEOUT, REPORT_FORMATS
from auditor.agent.agent import DEFAULT_MAX_TURNS
from auditor.scanners.batch import MAX_FILES_PER_BATCH, MAX_BATCH_TOKENS

DEFAULT_EXTENSION = [".py", ".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".vue", ".php", ".java", ".kt", ".kts", ".go", ".rs", ".rb", ".cs", ".swift", ".m", ".mm", ".scala", ".pl", ".pm", ".sh", ".bash", ".lua", ".dart"]

DEFAULT_SKIP_DIRS = {
    "test", "tests", "testing", "spec", "__pycache__", ".venv", "venv",
    "node_modules", "vendor", "third_party", "thirdparty", "generated",
    "build", "dist", "site-packages", ".git"
}

def parse_args(args=None):
    parser = argparse.ArgumentParser(prog="repo-auditor", description="Audit a code repository.")
    parser.add_argument("repo_path", nargs="?", help="Target repository directory")
    parser.add_argument("--scans", type=str, default="all", help="Comma-separated list of scanners. Default: all")
    parser.add_argument("--list", action="store_true", help="List available scan plugins and exit")
    parser.add_argument("--model", type=str, help="Specify the LLM model to use for scanning. Default: qwen-coder-64k:latest", default="qwen-coder-64k:latest")
    parser.add_argument("--ollama", type=str, help="Specify the Ollama host to use for scanning. Default: http://localhost:11434", default="http://localhost:11434")
    parser.add_argument("--ledger", type=str, help="Specify the ledger file to use for scanning. Default: findings.json", default="findings.json")
    parser.add_argument("--report", type=str, default=None, help="Specify the report file to write. Default: report.md, or report.sarif with --format sarif")
    parser.add_argument("--format", choices=sorted(REPORT_FORMATS), default="md", help="Report format: md (Markdown) or sarif (SARIF 2.1.0, for GitHub code scanning and SARIF viewers). Default: md")
    parser.add_argument("--extensions", type=str, help="Comma-separated list of file extensions to include in the audit, replacing the defaults. Default: all supported extensions.", default=",".join(DEFAULT_EXTENSION))
    parser.add_argument("--add-extensions", type=str, default="", help="Comma-separated list of file extensions to add to the defaults (or to --extensions).")
    parser.add_argument("--max-turns", type=int, default=DEFAULT_MAX_TURNS, help=f"Maximum model turns for agentic scanners (retries don't count). Default: {DEFAULT_MAX_TURNS}")
    parser.add_argument("--skip-dirs", type=str, help="Comma-separated list of directories to skip during the audit, replacing the defaults.", default=",".join(DEFAULT_SKIP_DIRS))
    parser.add_argument("--add-skip-dirs", type=str, default="", help="Comma-separated list of directories to skip in addition to the defaults (or to --skip-dirs).")
    parser.add_argument("--batch-max-files", type=int, default=MAX_FILES_PER_BATCH, help=f"batch scanner: maximum files reviewed together in one request. Default: {MAX_FILES_PER_BATCH}")
    parser.add_argument("--batch-max-tokens", type=int, default=MAX_BATCH_TOKENS, help=f"batch scanner: maximum estimated tokens of code in one request. Default: {MAX_BATCH_TOKENS}")
    parser.add_argument("--timeout", type=float, default=DEFAULT_REQUEST_TIMEOUT, help=f"Seconds allowed for a single model request before it is treated as failed. Default: {DEFAULT_REQUEST_TIMEOUT}")
    
    parsed = parser.parse_args(args)

    if parsed.report is None:
        parsed.report = REPORT_FORMATS[parsed.format][1]
    if parsed.batch_max_files < 1 or parsed.batch_max_tokens < 1:
        parser.error("--batch-max-files and --batch-max-tokens must be at least 1")

    if not parsed.repo_path and not parsed.list:
        parser.print_help()
        sys.exit(1)

    # An empty --extensions means "all extensions", so there's nothing to add to.
    extensions = _normalize_extensions(_split_list(parsed.extensions))
    if extensions:
        extensions = _unique(extensions + _normalize_extensions(_split_list(parsed.add_extensions)))
    parsed.extensions = extensions or None

    skip_dirs = _unique(_split_list(parsed.skip_dirs) + _split_list(parsed.add_skip_dirs))
    parsed.skip_dirs = skip_dirs or None

    return parsed

def _split_list(value: str | None) -> list[str]:
    """Splits a comma-separated CLI value, dropping blanks (so "a,,b," -> ["a", "b"])."""
    return [item.strip() for item in (value or "").split(",") if item.strip()]

def _normalize_extensions(extensions: list[str]) -> list[str]:
    """Lowercases and adds the leading dot, so "PY" and ".py" both mean ".py"."""
    return [ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions]

def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))

def list_scanners():
    print("Available scan plugins:")

    registry = get_available_scanners()
    for scan_id, cls in sorted(registry.items()):
        state = "" if cls.auto_enabled else "  (disabled: module name starts with '_')"
        print(f"  {scan_id:<12} {cls.name}{state}")

    return 0

def main(args=None):
    parsed_args = parse_args(args)

    # Library modules report retries and recoverable failures through `logging`.
    logging.basicConfig(level=logging.WARNING, format="    ! %(message)s")
    
    if parsed_args.list:
        return list_scanners()
    
    target = Path(parsed_args.repo_path).resolve()

    if not target.is_dir():
        print(f"[!] Target directory does not exist: {target}")
        return 1

    registry = get_available_scanners()

    # Fail fast on typos rather than silently running a subset of the requested scanners.
    if parsed_args.scans.lower() != "all":
        unknown_ids = [s.strip().lower() for s in parsed_args.scans.split(",") if s.strip().lower() not in registry]
        if unknown_ids:
            print(f"[!] Unknown scanner(s): {', '.join(unknown_ids)}. Use --list to see available scanners.")
            return 1

    selected_scanners, skipped_ids = filter_scanners(parsed_args.scans, registry)

    if skipped_ids:
        print(f"[*] Disabled plugin(s) excluded from 'all': {', '.join(sorted(skipped_ids))}")

    if not selected_scanners:
        print("[!] No scanners selected. Exiting.")
        return 1

    print(f"Starting audit on {target.name} with {len(selected_scanners)} scanner(s)...")
    
    print(f"Target directory: {target}")
    print(f"Extensions to include: {parsed_args.extensions if parsed_args.extensions else 'all'}")
    print(f"Directories to skip: {parsed_args.skip_dirs if parsed_args.skip_dirs else 'default skip dirs'}")
    print(f"Ledger file: {parsed_args.ledger}")
    print(f"Report file: {parsed_args.report} ({parsed_args.format})")
    print(f"Max agent turns: {parsed_args.max_turns}")

    try:
        return _run_audit(target, selected_scanners, parsed_args)
    except KeyboardInterrupt:
        # Ctrl+C stops the whole run, whichever scanner (or the critic) is active. In-flight
        # model requests are abandoned rather than waited on (see interruptible_chat).
        print(f"\n[!] Interrupted by user. Findings recorded so far remain in the ledger: {parsed_args.ledger}")
        return 130

def _run_audit(target: Path, selected_scanners: list, parsed_args) -> int:
    return execute_audit(
        target_dir=target,
        scanners_to_run=selected_scanners,
        model=parsed_args.model,
        ollama_host=parsed_args.ollama,
        ledger_file=parsed_args.ledger,
        report_file=parsed_args.report,
        report_format=parsed_args.format,
        extensions=parsed_args.extensions if parsed_args.extensions else None,
        skip_dirs=parsed_args.skip_dirs if parsed_args.skip_dirs else None,
        max_turns=parsed_args.max_turns,
        request_timeout=parsed_args.timeout,
        scanner_options={
            "batch_max_files": parsed_args.batch_max_files,
            "batch_max_tokens": parsed_args.batch_max_tokens,
        },
        on_progress=lambda msg: print(f"{msg}"),
        on_warning=lambda msg: print(f"{msg}"),
        on_error=lambda msg: print(f"{msg}"),
    )