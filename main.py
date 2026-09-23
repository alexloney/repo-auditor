import argparse
import importlib
import inspect
import pkgutil
from pathlib import Path

import scanners
from scanners.base import BaseScanner
from evaluator import run_evaluation
import ollama

client = ollama.Client(host="http://192.168.86.5:11434")

def get_available_scanners() -> dict[str, type[BaseScanner]]:
    """Dynamically loads all BaseScanner subclasses from the scanners package.

    Modules whose filename starts with '_' are still loadable by name but are
    excluded from the default 'all' selection.
    """
    registry = {}
    
    # Iterate through all files in the scanners/ directory
    for _, module_name, _ in pkgutil.iter_modules(scanners.__path__):
        module = importlib.import_module(f"scanners.{module_name}")
        
        # Find classes that inherit from BaseScanner (but ignore the base class itself)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseScanner) and obj is not BaseScanner:
                obj.auto_enabled = not module_name.startswith("_")
                registry[obj.id] = obj
                
    return registry

def main():
    parser = argparse.ArgumentParser(description="Pluggable LLM Repository Auditor")
    parser.add_argument("repo_path", type=str, nargs="?", help="Target repository directory")
    parser.add_argument("--scans", type=str, default="all", 
                        help="Comma-separated list of scans (e.g., shallow,taint,memory). Default: all")
    parser.add_argument("--list", action="store_true", help="List available scan plugins and exit")
    args = parser.parse_args()

    # Load all plugins dynamically
    available_scanners = get_available_scanners()

    if args.list:
        print("Available scan plugins:")
        for scan_id, cls in sorted(available_scanners.items()):
            state = "" if cls.auto_enabled else "  (disabled: module name starts with '_')"
            print(f"  {scan_id:<12} {cls.name}{state}")
        return

    if not args.repo_path:
        parser.error("repo_path is required unless --list is given")

    target_dir = Path(args.repo_path).resolve()
    ledger_path = target_dir / "findings.json"

    # Parse CLI selection
    if args.scans.lower() == "all":
        selected_ids = [sid for sid, cls in available_scanners.items() if cls.auto_enabled]
        skipped = [sid for sid, cls in available_scanners.items() if not cls.auto_enabled]
        if skipped:
            print(f"[*] Disabled plugin(s) excluded from 'all': {', '.join(sorted(skipped))}")
    else:
        selected_ids = [s.strip().lower() for s in args.scans.split(",")]

    # Execute the requested scans
    for scan_id in selected_ids:
        if scan_id not in available_scanners:
            print(f"[*] Skipping unknown scan plugin: '{scan_id}'")
            continue
            
        scanner_class = available_scanners[scan_id]
        print(f"\n--- Running {scanner_class.name} ---")
        
        scanner_instance = scanner_class(client, target_dir, ledger_path)
        scanner_instance.run()

    # The evaluation pass always runs last, independent of the plugins
    print("\n--- Running Final Evaluation ---")
    run_evaluation(client, target_dir, ledger_path)

if __name__ == "__main__":
    main()