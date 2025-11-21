import importlib
import pkgutil
import inspect
import logging
import os
from typing import List, Type
from .vulnerability_testers.base_tester_async import VulnerabilityTester

class TesterRegistry:
    """
    Registry for vulnerability testers.
    Handles discovery and registration of tester plugins.
    """
    _testers: List[Type[VulnerabilityTester]] = []
    _logger = logging.getLogger("TesterRegistry")

    @classmethod
    def register(cls, tester_class: Type[VulnerabilityTester]):
        """Register a tester class."""
        if tester_class not in cls._testers:
            cls._testers.append(tester_class)
            cls._logger.debug(f"Registered tester: {tester_class.__name__}")

    @classmethod
    def get_testers(cls) -> List[Type[VulnerabilityTester]]:
        """Get all registered tester classes."""
        return cls._testers

    @classmethod
    def discover_testers(cls):
        """
        Automatically discover and register testers from the vulnerability_testers package.
        """
        # Import the package containing testers
        from . import vulnerability_testers
        
        package_path = os.path.dirname(vulnerability_testers.__file__)
        
        for _, name, _ in pkgutil.iter_modules([package_path]):
            if name.startswith('base_tester'):
                continue
                
            try:
                module = importlib.import_module(f".vulnerability_testers.{name}", package="web_security_scanner.modules")
                
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, VulnerabilityTester) and 
                        obj is not VulnerabilityTester):
                        cls.register(obj)
            except Exception as e:
                cls._logger.error(f"Failed to load module {name}: {e}")
