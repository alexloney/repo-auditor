from abc import ABC, abstractmethod
from pathlib import Path
import ollama

class BaseScanner(ABC):
    # Class attributes allow the CLI to read the ID without instantiating the class
    id: str = ""
    name: str = ""
    # Set by the plugin loader; False for modules whose filename starts with '_'.
    auto_enabled: bool = True

    def __init__(self, client: ollama.Client, target_dir: Path, ledger_path: Path):
        self.client = client
        self.target_dir = target_dir
        self.ledger_path = ledger_path

    @abstractmethod
    def run(self) -> None:
        """Executes the scanning logic and appends to the ledger."""
        pass