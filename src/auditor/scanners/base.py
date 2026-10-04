from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable
import ollama

from ..agent.agent import DEFAULT_MAX_TURNS

class BaseScanner(ABC):
    # Class attributes allow the CLI to read the ID without instantiating the class
    id: str = ""
    name: str = ""
    # Set by the plugin loader; False for modules whose filename starts with '_'.
    auto_enabled: bool = True

    def __init__(self, 
                 client: ollama.Client, 
                 model: str,
                 target_dir: Path, 
                 ledger_path: Path,
                 extensions: list[str] | None = None,
                 skip_dirs: list[str] | None = None,
                 max_turns: int = DEFAULT_MAX_TURNS,
                 on_progress: Callable[[str], None] = None,
                 on_warning: Callable[[str], None] = None,
                 on_error: Callable[[str], None] = None):
        self.client = client
        self.model = model
        self.target_dir = target_dir
        self.ledger_path = ledger_path
        self.on_progress = on_progress or (lambda msg: None)
        self.on_warning = on_warning or (lambda msg: None)
        self.on_error = on_error or (lambda msg: None)
        self.extensions = extensions
        self.skip_dirs = skip_dirs
        # Turn budget for agentic scanners; ignored by scanners that don't run an agent loop.
        self.max_turns = max_turns

    @abstractmethod
    def run(self) -> None:
        """Executes the scanning logic and appends to the ledger."""
        pass