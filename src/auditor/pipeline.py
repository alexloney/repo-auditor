import importlib
import inspect
import json
import pkgutil
from typing import Callable
import ollama
from pathlib import Path

from auditor import scanners
from auditor.scanners.base import BaseScanner
from auditor.agent.agent import DEFAULT_MAX_TURNS
from auditor.evaluator.dedupe import dedupe_findings
from auditor.evaluator.grounding import ground_findings
from auditor.evaluator.critic import verify_findings
from auditor.evaluator.reporter import write_report
from auditor.evaluator.sarif import write_sarif_report

# Seconds allowed for one model request. Generous, because a non-streamed request only
# returns once the whole answer (and any reasoning) has been generated.
DEFAULT_REQUEST_TIMEOUT = 1800

# Report format -> (writer, default file name)
REPORT_FORMATS = {
    "md": (write_report, "report.md"),
    "sarif": (write_sarif_report, "report.sarif"),
}

def get_available_scanners() -> dict[str, type[BaseScanner]]:
    """Dynamically loads all BaseScanner subclasses from the scanners package.

    Modules whose filename starts with '_' are still loadable by name but are
    excluded from the default 'all' selection.
    """
    registry = {}
    
    # Iterate through all files in the scanners/ directory
    for _, module_name, _ in pkgutil.iter_modules(scanners.__path__):
        module = importlib.import_module(f"auditor.scanners.{module_name}")
        
        # Find concrete BaseScanner subclasses *defined* in this module. Classes merely imported
        # into it (e.g. a parent scanner being subclassed) are registered by their own module,
        # so their auto_enabled flag comes from the right filename.
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if (issubclass(obj, BaseScanner)
                    and obj.__module__ == module.__name__
                    and not inspect.isabstract(obj)):
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

def _prefixed(callback: Callable[[str], None], label: str) -> Callable[[str], None]:
    """Wraps a callback so every message is indented and tagged with the emitting component."""
    return lambda msg: callback(f"  {label} {msg}")

def execute_audit(target_dir: Path, 
                  scanners_to_run: list[type[BaseScanner]], 
                  model: str, 
                  ollama_host: str, 
                  ledger_file: str, 
                  report_file: str,
                  extensions: list[str] | None = None,
                  skip_dirs: list[str] | None = None,
                  max_turns: int = DEFAULT_MAX_TURNS,
                  request_timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
                  report_format: str = "md",
                  on_progress: Callable[[str], None] = None,
                  on_warning: Callable[[str], None] = None,
                  on_error: Callable[[str], None] = None) -> int:
    """Runs the scanners, verifies the findings, and writes the report. Returns a process exit code."""
    # Without a timeout, one stalled request blocks the whole run forever. The timeout must
    # cover a full (non-streamed) generation, including a thinking model's reasoning.
    client = ollama.Client(host=f"{ollama_host}", timeout=request_timeout)
    # NOTE: The ledger is intentionally NOT cleared between runs. Scanners only append to it,
    # so findings from earlier runs (possibly against other repos) are re-verified and
    # re-reported. This is deliberate for now, to make debugging the critic/reporter easier
    # without re-running the scanners. Delete the ledger file manually for a clean run.
    ledger_path = Path(ledger_file).resolve()
    report_path = Path(report_file).resolve()

    on_progress = on_progress or (lambda _: None)
    on_warning = on_warning or (lambda _: None)
    on_error = on_error or (lambda _: None)

    for scanner_class in scanners_to_run:
        label = f"[{scanner_class.name}]"
        scanner_instance = scanner_class(
            client=client,
            model=model,
            target_dir=target_dir,
            ledger_path=ledger_path,
            extensions=extensions,
            skip_dirs=skip_dirs,
            max_turns=max_turns,
            on_progress=_prefixed(on_progress, label),
            on_warning=_prefixed(on_warning, label),
            on_error=_prefixed(on_error, label),
        )
        scanner_instance.run()

    if not ledger_path.exists():
        on_progress("No findings ledger found. Skipping evaluation and report generation.")
        return 0

    raw_findings = []
    try:
        with open(ledger_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    raw_findings.append(json.loads(line))
                except json.JSONDecodeError:
                    on_warning(f"Skipping malformed ledger entry at line {lineno}")
    except OSError as e:
        on_error(f"Failed to read ledger: {e}")
        return 1

    grounded_findings, dropped, corrected = ground_findings(
        target_dir, raw_findings, on_warning=_prefixed(on_warning, "[Evidence]"))
    on_progress(f"Evidence check: {dropped} finding(s) dropped, {corrected} line number(s) corrected.")

    unique_findings = dedupe_findings(grounded_findings)
    on_progress(f"{len(unique_findings)} unique finding(s) before verification.")
    
    if unique_findings:
        verified_findings = verify_findings(client, 
                                            model, 
                                            target_dir, 
                                            unique_findings,
                                            extensions,
                                            skip_dirs,
                                            on_progress=_prefixed(on_progress, "[Critic]"),
                                            on_warning=_prefixed(on_warning, "[Critic]"),
                                            on_error=_prefixed(on_error, "[Critic]"))
        on_progress(f"{len(verified_findings)} finding(s) survived critic pass.")
    else:
        verified_findings = []
        on_progress("No findings to verify.")

    writer, _ = REPORT_FORMATS[report_format]
    writer(target_dir, report_path, verified_findings)
    on_progress(f"Report written to {report_path}")
    return 0
