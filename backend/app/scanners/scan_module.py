from abc import ABC, abstractmethod

from app.models.scan_result import ScanResult
from app.models.target import Target


class ScanModule(ABC):
    """
    Abstract base class defining the interface for all scan modules.
    
    All scanning modules (port scanning, web security, SSL/TLS analysis, etc.)
    must inherit from this class and implement the scan() method.
    
    This ensures consistent method signatures and return types across all
    scan modules, enabling the Scan Orchestrator to coordinate them uniformly.
    """
    
    @abstractmethod
    async def scan(self, target: Target) -> ScanResult:
        """
        Execute the scan for the given target.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing the module name, execution status,
            execution time, and any findings discovered during the scan
            
        Raises:
            Exception: If the scan encounters an unexpected error
        """
        pass
