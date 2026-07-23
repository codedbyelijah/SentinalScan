from pydantic import BaseModel, Field

from app.models.enums import Severity
from app.models.scan_result import ScanResult


class RiskAnalysisResult(BaseModel):
    """Represents the result of risk analysis on scan results."""
    
    results: list[ScanResult] = Field(
        description="List of normalized scan results from all modules"
    )
    overall_risk: Severity = Field(
        description="Overall risk level based on highest severity finding"
    )
    security_summary: str = Field(
        description="Human-readable summary of the security assessment"
    )
    total_findings: int = Field(
        description="Total number of findings across all scan results"
    )
    warnings: int = Field(
        description="Number of MEDIUM severity findings (warnings)"
    )
    errors: int = Field(
        description="Number of HIGH and CRITICAL severity findings (errors)"
    )
