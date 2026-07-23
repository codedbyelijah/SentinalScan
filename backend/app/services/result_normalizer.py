from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult


class ResultNormalizationError(Exception):
    """Raised when result normalization fails."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ResultNormalizer:
    """
    Service for normalizing and validating scan results.
    
    Validates ScanResult objects from all scan modules to ensure
    data integrity before risk analysis and report generation.
    """
    
    @staticmethod
    def normalize(results: list[ScanResult]) -> list[ScanResult]:
        """
        Normalize and validate scan results.
        
        Validates the structure and data integrity of ScanResult objects
        from all scan modules. Preserves both successful and failed results.
        
        Args:
            results: List of ScanResult objects from scan modules
            
        Returns:
            Validated list of ScanResult objects
            
        Raises:
            ResultNormalizationError: If any result is malformed or invalid
        """
        if not isinstance(results, list):
            raise ResultNormalizationError(
                "Results must be a list of ScanResult objects"
            )
        
        for i, result in enumerate(results):
            ResultNormalizer._validate_scan_result(result, i)
        
        return results
    
    @staticmethod
    def _validate_scan_result(result: ScanResult, index: int) -> None:
        """
        Validate a single ScanResult object.
        
        Args:
            result: The ScanResult to validate
            index: The index of the result in the list (for error messages)
            
        Raises:
            ResultNormalizationError: If the result is invalid
        """
        if not isinstance(result, ScanResult):
            raise ResultNormalizationError(
                f"Result at index {index} is not a ScanResult object"
            )
        
        # Validate required fields exist and are correct type
        if not isinstance(result.module_name, str) or not result.module_name:
            raise ResultNormalizationError(
                f"Result at index {index} has invalid or missing module_name"
            )
        
        if not isinstance(result.status, Status):
            raise ResultNormalizationError(
                f"Result at index {index} has invalid status: {result.status}"
            )
        
        if not isinstance(result.execution_time, (int, float)) or result.execution_time < 0:
            raise ResultNormalizationError(
                f"Result at index {index} has invalid execution_time: {result.execution_time}"
            )
        
        # Validate findings list
        if not isinstance(result.findings, list):
            raise ResultNormalizationError(
                f"Result at index {index} has invalid findings field"
            )
        
        # Validate each finding
        for j, finding in enumerate(result.findings):
            ResultNormalizer._validate_finding(finding, index, j)
    
    @staticmethod
    def _validate_finding(finding: Finding, result_index: int, finding_index: int) -> None:
        """
        Validate a single Finding object.
        
        Args:
            finding: The Finding to validate
            result_index: The index of the parent ScanResult
            finding_index: The index of the finding in the list
            
        Raises:
            ResultNormalizationError: If the finding is invalid
        """
        if not isinstance(finding, Finding):
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                "is not a Finding object"
            )
        
        # Validate required fields exist and are correct type
        if not isinstance(finding.title, str) or not finding.title:
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                "has invalid or missing title"
            )
        
        if not isinstance(finding.description, str) or not finding.description:
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                "has invalid or missing description"
            )
        
        if not isinstance(finding.severity, Severity):
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                f"has invalid severity: {finding.severity}"
            )
        
        if not isinstance(finding.category, Category):
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                f"has invalid category: {finding.category}"
            )
        
        if not isinstance(finding.affected_target, str) or not finding.affected_target:
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                "has invalid or missing affected_target"
            )
        
        if not isinstance(finding.recommendation, str) or not finding.recommendation:
            raise ResultNormalizationError(
                f"Finding at index {finding_index} in result {result_index} "
                "has invalid or missing recommendation"
            )
