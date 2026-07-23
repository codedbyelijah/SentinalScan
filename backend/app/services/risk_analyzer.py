from app.models.enums import Severity
from app.models.risk_analysis_result import RiskAnalysisResult
from app.models.scan_result import ScanResult


class RiskAnalysisError(Exception):
    """Raised when risk analysis fails."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class RiskAnalyzer:
    """
    Service for analyzing scan results and calculating risk levels.
    
    Analyzes normalized scan results to determine overall security risk,
    generate security summaries, and count findings by severity.
    """
    
    # Severity order from lowest to highest
    SEVERITY_ORDER = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4
    }
    
    @staticmethod
    def analyze(results: list[ScanResult]) -> RiskAnalysisResult:
        """
        Analyze scan results and calculate risk metrics.
        
        Analyzes the severity distribution of findings across all scan results,
        calculates overall risk level, generates a security summary, and counts
        findings by severity category.
        
        Args:
            results: List of normalized ScanResult objects from scan modules
            
        Returns:
            RiskAnalysisResult with overall risk, summary, and counts
            
        Raises:
            RiskAnalysisError: If analysis fails
        """
        if not isinstance(results, list):
            raise RiskAnalysisError(
                "Results must be a list of ScanResult objects"
            )
        
        # Count findings by severity
        severity_counts = {
            Severity.INFO: 0,
            Severity.LOW: 0,
            Severity.MEDIUM: 0,
            Severity.HIGH: 0,
            Severity.CRITICAL: 0
        }
        
        total_findings = 0
        
        for result in results:
            for finding in result.findings:
                severity_counts[finding.severity] += 1
                total_findings += 1
        
        # Calculate overall risk (highest severity present)
        overall_risk = RiskAnalyzer._calculate_overall_risk(severity_counts)
        
        # Calculate warnings (MEDIUM) and errors (HIGH + CRITICAL)
        warnings = severity_counts[Severity.MEDIUM]
        errors = severity_counts[Severity.HIGH] + severity_counts[Severity.CRITICAL]
        
        # Generate security summary
        security_summary = RiskAnalyzer._generate_security_summary(
            overall_risk,
            total_findings,
            warnings,
            errors
        )
        
        return RiskAnalysisResult(
            results=results,
            overall_risk=overall_risk,
            security_summary=security_summary,
            total_findings=total_findings,
            warnings=warnings,
            errors=errors
        )
    
    @staticmethod
    def _calculate_overall_risk(severity_counts: dict[Severity, int]) -> Severity:
        """
        Calculate overall risk based on highest severity finding.
        
        Args:
            severity_counts: Dictionary of severity to count
            
        Returns:
            Highest severity level present in findings
        """
        # Check from highest to lowest severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity_counts[severity] > 0:
                return severity
        
        # No findings - default to INFO
        return Severity.INFO
    
    @staticmethod
    def _generate_security_summary(
        overall_risk: Severity,
        total_findings: int,
        warnings: int,
        errors: int
    ) -> str:
        """
        Generate a human-readable security summary.
        
        Args:
            overall_risk: The calculated overall risk level
            total_findings: Total number of findings
            warnings: Number of MEDIUM severity findings
            errors: Number of HIGH and CRITICAL severity findings
            
        Returns:
            Human-readable security summary
        """
        if total_findings == 0:
            return "No security findings detected. The target appears secure based on the performed scans."
        
        summary_parts = []
        
        # Add overall risk assessment
        risk_descriptions = {
            Severity.INFO: "informational",
            Severity.LOW: "low",
            Severity.MEDIUM: "moderate",
            Severity.HIGH: "high",
            Severity.CRITICAL: "critical"
        }
        
        summary_parts.append(
            f"Overall security risk is {risk_descriptions[overall_risk]}."
        )
        
        # Add finding count
        summary_parts.append(
            f"Found {total_findings} total finding(s)."
        )
        
        # Add breakdown by severity
        if errors > 0:
            summary_parts.append(f"{errors} critical/high severity issue(s) require immediate attention.")
        
        if warnings > 0:
            summary_parts.append(f"{warnings} moderate severity warning(s) should be addressed.")
        
        # Add recommendation based on risk level
        if overall_risk in [Severity.HIGH, Severity.CRITICAL]:
            summary_parts.append("Immediate remediation is recommended.")
        elif overall_risk == Severity.MEDIUM:
            summary_parts.append("Remediation should be prioritized.")
        elif overall_risk == Severity.LOW:
            summary_parts.append("Remediation is recommended when convenient.")
        else:
            summary_parts.append("Regular monitoring is recommended.")
        
        return " ".join(summary_parts)
