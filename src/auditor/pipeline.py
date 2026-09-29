import importlib
import inspect
import pkgutil
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