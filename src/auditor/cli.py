import argparse
import importlib
import sys
from pathlib import Path
from auditor.pipeline import execute_audit, get_available_scanners, filter_scanners

def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Audit a code repository.")
    parser.add_argument("repo_path", nargs="?", help="Target repository directory")
    parser.add_argument("--scans", type=str, default="all", help="Comma-separated list of scanners. Default: all")
    parser.add_argument("--list", action="store_true", help="List available scan plugins and exit")
    parser.add_argument("--model", type=str, help="Specify the LLM model to use for scanning. Default: qwen-coder-64k:latest", default="qwen-coder-64k:latest")
    parser.add_argument("--ollama", type=str, help="Specify the Ollama host to use for scanning. Default: localhost:11434", default="localhost:11434")
    parser.add_argument("--ledger", type=str, help="Specify the ledger file to use for scanning. Default: ledger.json", default="findings.json")
    parser.add_argument("--report", type=str, help="Specify the report file to use for scanning. Default: report.json", default="report.md")
    
    parsed = parser.parse_args(args)

    if not parsed.repo_path and not parsed.list:
        parser.print_help()
        sys.exit(1)

    return parsed

def list_scanners():
    print("Available scan plugins:")

    registry = get_available_scanners()
    for scan_id, cls in sorted(registry.items()):
        state = "" if cls.auto_enabled else "  (disabled: module name starts with '_')"
        print(f"  {scan_id:<12} {cls.name}{state}")

    return 0

def main(args=None):
    parsed_args = parse_args(args)

    if parsed_args.list:
        return list_scanners()

    registry = get_available_scanners()
    selected_scanners, skipped_ids = filter_scanners(parsed_args.scans, registry)

    if skipped_ids:
        print(f"[*] Disabled plugin(s) excluded from 'all': {', '.join(sorted(skipped_ids))}")

    return execute_audit(
        target_dir=Path(parsed_args.repo_path),
        scanners_to_run=selected_scanners,
        model=parsed_args.model,
        ollama_host=parsed_args.ollama,
        ledger_file=parsed_args.ledger,
        report_file=parsed_args.report
    )