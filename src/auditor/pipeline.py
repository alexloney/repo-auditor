import importlib
import inspect
import pkgutil
import ollama
from pathlib import Path

from auditor import scanners
from auditor.scanners.base import BaseScanner

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
                  skip_dirs: list[str] | None = None):
    client = ollama.Client(host=f"{ollama_host}")
    ledger_path = Path(ledger_file).resolve()

    # Loop through scanners and 
    for scanner_class in scanners_to_run:
        scanner_instance = scanner_class(
            client=client,
            model=model,
            target_dir=target_dir,
            ledger_path=ledger_path,
            extensions=extensions,
            skip_dirs=skip_dirs,
            on_progress=lambda msg: print(f"  [{scanner_class.name}] " + msg),  # Replace with appropriate callback
            on_warning=lambda msg: print(f"  [{scanner_class.name}] " + msg),  # Replace with appropriate callback
            on_error=lambda msg: print(f"  [{scanner_class.name}] " + msg),  # Replace with appropriate callback
        )
        scanner_instance.run()

    # Run verification on each finding
    # TODO: Implement verification

    # TODO: Do I want to add additional validation and formatting?

    # Run report generation on each finding
    # TODO: Implement report generation



    