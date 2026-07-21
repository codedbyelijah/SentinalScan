from app.models.enums import ScanMode
from app.models.scan_request import ScanRequest
from app.models.target import Target


class ScanConfigurationError(Exception):
    """Raised when scan configuration is invalid."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ScanConfiguration:
    """
    Service for creating scan configurations.
    
    Validates scan modes and module selections, and builds
    ScanRequest models compatible with the Scan Orchestrator.
    """
    
    def __init__(self, available_modules: list[str]):
        """
        Initialize the configuration service with available modules.
        
        Args:
            available_modules: List of available scan module names
        """
        self.available_modules = set(available_modules)
    
    def create_full_scan(self, target: Target) -> ScanRequest:
        """
        Create a Full Scan configuration.
        
        Full Scan mode runs all available modules.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanRequest configured for Full Scan mode
            
        Raises:
            ScanConfigurationError: If configuration is invalid
        """
        return ScanRequest(
            target=target,
            scan_mode=ScanMode.FULL,
            enabled_modules=[]
        )
    
    def create_custom_scan(self, target: Target, enabled_modules: list[str]) -> ScanRequest:
        """
        Create a Custom Scan configuration.
        
        Custom Scan mode runs only the specified modules.
        
        Args:
            target: The validated Target model to scan
            enabled_modules: List of module names to enable
            
        Returns:
            ScanRequest configured for Custom Scan mode
            
        Raises:
            ScanConfigurationError: If configuration is invalid
        """
        # Validate module names
        if not enabled_modules:
            raise ScanConfigurationError(
                "Custom scan requires at least one enabled module"
            )
        
        # Check for duplicate module names
        if len(enabled_modules) != len(set(enabled_modules)):
            raise ScanConfigurationError(
                "Duplicate module names in enabled_modules list"
            )
        
        # Validate each module name exists in available modules
        invalid_modules = []
        for module_name in enabled_modules:
            if module_name not in self.available_modules:
                invalid_modules.append(module_name)
        
        if invalid_modules:
            raise ScanConfigurationError(
                f"Invalid module names: {', '.join(invalid_modules)}. "
                f"Available modules: {', '.join(sorted(self.available_modules))}"
            )
        
        return ScanRequest(
            target=target,
            scan_mode=ScanMode.CUSTOM,
            enabled_modules=enabled_modules
        )
