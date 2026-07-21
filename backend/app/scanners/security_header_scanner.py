import re
import time

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.http_probe import HttpProbe
from app.scanners.scan_module import ScanModule


class SecurityHeaderScanner(ScanModule):
    """
    Asynchronous security header analysis module.
    
    Analyzes HTTP response headers for security best practices.
    Checks for presence and proper configuration of security headers.
    """
    
    # Required security headers to check
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the SecurityHeaderScanner module.
        
        Args:
            timeout: Request timeout in seconds. Default: 10.0
            
        Raises:
            ValueError: If timeout is not positive
        """
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        
        self.timeout = timeout
        self.http_probe = HttpProbe(timeout=timeout)
    
    async def scan(self, target: Target) -> ScanResult:
        """
        Analyze security headers for the target.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing security header findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Determine which protocols to try
            protocols = self.http_probe.determine_protocols(target)
            
            # Try each protocol until one succeeds
            headers = None
            final_url = None
            for protocol in protocols:
                try:
                    result = await self.http_probe.probe_http(target, protocol)
                    if result:
                        headers = result.get("response_headers", {})
                        final_url = result.get("final_url", target.normalized_target)
                        break
                except Exception:
                    # Try next protocol
                    continue
            
            if headers:
                # Analyze security headers
                findings.extend(self._analyze_headers(headers, final_url or target.normalized_target))
                status = Status.COMPLETED
            else:
                # All protocols failed
                error_finding = Finding(
                    title="Security Header Scan Failed",
                    description=f"Unable to connect to {target.normalized_target} via HTTP or HTTPS",
                    severity=Severity.HIGH,
                    category=Category.WEB_SECURITY,
                    affected_target=target.normalized_target,
                    recommendation="Verify the target is accessible and running a web server."
                )
                findings.append(error_finding)
                status = Status.FAILED
            
        except Exception as e:
            # Handle unexpected errors gracefully
            status = Status.FAILED
            error_finding = Finding(
                title="Security Header Scan Failed",
                description=f"Security header scan encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="SecurityHeaderScanner",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    def _analyze_headers(self, headers: dict, target: str) -> list[Finding]:
        """
        Analyze security headers for presence and configuration.
        
        Args:
            headers: Dictionary of HTTP response headers
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Check each required security header
        for header_name in self.SECURITY_HEADERS:
            header_value = self._get_header_value(headers, header_name)
            
            if not header_value:
                # Header is missing
                findings.append(self._create_missing_header_finding(header_name, target))
            else:
                # Header is present - validate configuration
                validation_finding = self._validate_header(header_name, header_value, target)
                if validation_finding:
                    findings.append(validation_finding)
        
        return findings
    
    def _get_header_value(self, headers: dict, header_name: str) -> str | None:
        """
        Get header value (case-insensitive lookup).
        
        Args:
            headers: Dictionary of HTTP headers
            header_name: Name of the header to lookup
            
        Returns:
            Header value if found, None otherwise
        """
        for key, value in headers.items():
            if key.lower() == header_name.lower():
                return value
        return None
    
    def _create_missing_header_finding(self, header_name: str, target: str) -> Finding:
        """
        Create a finding for a missing security header.
        
        Args:
            header_name: Name of the missing header
            target: The target URL
            
        Returns:
            Finding object
        """
        return Finding(
            title=f"Missing Security Header: {header_name}",
            description=f"The {header_name} header is not set. This header is important for web security.",
            severity=Severity.MEDIUM,
            category=Category.WEB_SECURITY,
            affected_target=target,
            recommendation=f"Implement the {header_name} header to improve security. Refer to security best practices for proper configuration."
        )
    
    def _validate_header(self, header_name: str, header_value: str, target: str) -> Finding | None:
        """
        Validate a security header's configuration.
        
        Args:
            header_name: Name of the header
            header_value: Value of the header
            target: The target URL
            
        Returns:
            Finding object if misconfigured, None otherwise
        """
        header_lower = header_name.lower()
        
        if header_lower == "content-security-policy":
            return self._validate_csp(header_value, target)
        elif header_lower == "strict-transport-security":
            return self._validate_hsts(header_value, target)
        elif header_lower == "x-frame-options":
            return self._validate_x_frame_options(header_value, target)
        elif header_lower == "x-content-type-options":
            return self._validate_x_content_type_options(header_value, target)
        elif header_lower == "referrer-policy":
            return self._validate_referrer_policy(header_value, target)
        elif header_lower == "permissions-policy":
            return self._validate_permissions_policy(header_value, target)
        
        return None
    
    def _validate_csp(self, value: str, target: str) -> Finding | None:
        """Validate Content-Security-Policy header."""
        value_lower = value.lower()
        
        if "unsafe-inline" in value_lower or "unsafe-eval" in value_lower:
            return Finding(
                title="Misconfigured Content-Security-Policy",
                description=f"CSP contains unsafe directives: {value}",
                severity=Severity.MEDIUM,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes instead for script execution."
            )
        
        return None
    
    def _validate_hsts(self, value: str, target: str) -> Finding | None:
        """Validate Strict-Transport-Security header."""
        # Check max-age
        max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:  # Less than 1 year
                return Finding(
                    title="Misconfigured Strict-Transport-Security",
                    description=f"HSTS max-age is {max_age} seconds (less than recommended 31536000 seconds): {value}",
                    severity=Severity.LOW,
                    category=Category.WEB_SECURITY,
                    affected_target=target,
                    recommendation="Set max-age to at least 31536000 (1 year) for proper HSTS protection."
                )
            
            # Only check includeSubDomains if max-age is present and valid
            if "includesubdomains" not in value.lower():
                return Finding(
                    title="Misconfigured Strict-Transport-Security",
                    description=f"HSTS missing 'includeSubDomains' directive: {value}",
                    severity=Severity.LOW,
                    category=Category.WEB_SECURITY,
                    affected_target=target,
                    recommendation="Add 'includeSubDomains' directive to HSTS for comprehensive protection."
                )
        else:
            # max-age is missing entirely - this is a critical misconfiguration
            return Finding(
                title="Misconfigured Strict-Transport-Security",
                description=f"HSTS missing 'max-age' directive: {value}",
                severity=Severity.MEDIUM,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="HSTS must include a 'max-age' directive to be effective."
            )
        
        return None
    
    def _validate_x_frame_options(self, value: str, target: str) -> Finding | None:
        """Validate X-Frame-Options header."""
        value_lower = value.lower()
        
        if "allow-from" in value_lower:
            return Finding(
                title="Misconfigured X-Frame-Options",
                description=f"X-Frame-Options uses deprecated 'ALLOW-FROM' directive: {value}",
                severity=Severity.LOW,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Use Content-Security-Policy frame-ancestors directive instead of deprecated ALLOW-FROM."
            )
        
        return None
    
    def _validate_x_content_type_options(self, value: str, target: str) -> Finding | None:
        """Validate X-Content-Type-Options header."""
        value_lower = value.lower()
        
        if value_lower != "nosniff":
            return Finding(
                title="Misconfigured X-Content-Type-Options",
                description=f"X-Content-Type-Options should be 'nosniff', found: {value}",
                severity=Severity.LOW,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Set X-Content-Type-Options to 'nosniff' to prevent MIME type sniffing."
            )
        
        return None
    
    def _validate_referrer_policy(self, value: str, target: str) -> Finding | None:
        """Validate Referrer-Policy header."""
        value_lower = value.lower()
        
        if value_lower in ("no-referrer", "unsafe-url"):
            return Finding(
                title="Misconfigured Referrer-Policy",
                description=f"Referrer-Policy uses potentially insecure value: {value}",
                severity=Severity.LOW,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Use a more secure referrer policy such as 'strict-origin-when-cross-origin'."
            )
        
        return None
    
    def _validate_permissions_policy(self, value: str, target: str) -> Finding | None:
        """Validate Permissions-Policy header."""
        # For now, just report presence - value validation is complex
        # and can be added later if needed
        return None
