import importlib
import inspect
import json
import pkgutil
from typing import Callable
import ollama
from pathlib import Path

from auditor import scanners
from auditor.scanners.base import BaseScanner
from auditor.evaluator.dedupe import dedupe_findings
from auditor.evaluator.critic import verify_findings  
from auditor.evaluator.reporter import write_report

def get_available_scanners() -> dict[str, type[BaseScanner]]:
    """Dynamically loads all BaseScanner subclasses from the scanners package.

    Modules whose filename starts with '_' are still loadable by name but are
    excluded from the default 'all' selection.
    """
    registry = {}
    
    # Iterate through all files in the scanners/ directory
    for _, module_name, _ in pkgutil.iter_modules(scanners.__path__):
        module = importlib.import_module(f"auditor.scanners.{module_name}")
        
        # Find classes that inherit from BaseScanner (but ignore the base class itself)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, BaseScanner) and obj is not BaseScanner:
                obj.auto_enabled = not module_name.startswith("_")
                registry[obj.id] = obj
                
    return registry

def filter_scanners(requested_scans: str, available_scanners: dict[str, type[BaseScanner]]) -> tuple[list[type[BaseScanner]], list[str]]:
    """Filters scanners and returns (selected_scanners, skipped_ids)."""
    selected_ids = []
    skipped_ids = []

    if requested_scans.lower() == "all":
        selected_ids = [sid for sid, cls in available_scanners.items() if cls.auto_enabled]
        skipped_ids = [sid for sid, cls in available_scanners.items() if not cls.auto_enabled]
    else:
        selected_ids = [s.strip().lower() for s in requested_scans.split(",")]

    selected_scanners = [available_scanners[sid] for sid in selected_ids if sid in available_scanners]
    return selected_scanners, skipped_ids

def execute_audit(target_dir: Path, 
                  scanners_to_run: list[type[BaseScanner]], 
                  model: str, 
                  ollama_host: str, 
                  ledger_file: str, 
                  report_file: str,
                  extensions: list[str] | None = None,
                  skip_dirs: list[str] | None = None,
                  on_progress: Callable[[str], None] = None,
                  on_warning: Callable[[str], None] = None,
                  on_error: Callable[[str], None] = None):
    client = ollama.Client(host=f"{ollama_host}")
    ledger_path = Path(ledger_file).resolve()
    report_path = Path(report_file).resolve()

    # Loop through scanners and 
    for scanner_class in scanners_to_run:
        scanner_instance = scanner_class(
            client=client,
            model=model,
            target_dir=target_dir,
            ledger_path=ledger_path,
            extensions=extensions,
            skip_dirs=skip_dirs,
            on_progress=lambda msg: on_progress(f"  [{scanner_class.name}] {msg}") if on_progress else None,
            on_warning=lambda msg: on_warning(f"  [{scanner_class.name}] {msg}") if on_warning else None,
            on_error=lambda msg: on_error(f"  [{scanner_class.name}] {msg}") if on_error else None,
        )
        scanner_instance.run()

    if not ledger_path.exists():
        on_progress("No findings ledger found. Skipping evaluation and report generation.")
        return

    raw_findings = []
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    raw_findings.append(json.loads(line))
                except json.JSONDecodeError:
                    on_warning(f"Skipping malformed ledger entry at line {lineno}") if on_warning else None
    except OSError as e:
        on_error(f"Failed to read ledger: {e}")
        return

    unique_findings = dedupe_findings(raw_findings)
    on_progress(f"{len(unique_findings)} unique finding(s) before verification.") if on_progress else None
    
    if unique_findings:
        verified_findings = verify_findings(client, 
                                            model, 
                                            target_dir, 
                                            unique_findings, 
                                            on_progress=lambda msg: on_progress(f"  [Critic] {msg}") if on_progress else None, 
                                            on_warning=lambda msg: on_warning(f"  [Critic] {msg}") if on_warning else None, 
                                            on_error=lambda msg: on_error(f"  [Critic] {msg}") if on_error else None)
        on_progress(f"{len(verified_findings)} finding(s) survived critic pass.") if on_progress else None
    else:
        verified_findings = []
        on_progress("No findings survived verification.") if on_progress else None

    write_report(target_dir, verified_findings)
    on_progress(f"Report written to {report_path}") if on_progress else None
