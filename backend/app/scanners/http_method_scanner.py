import time

import httpx

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.http_probe import HttpProbe
from app.scanners.scan_module import ScanModule


class HTTPMethodScanner(ScanModule):
    """
    Asynchronous HTTP method analysis module.
    
    Discovers which HTTP methods are supported by the target
    and identifies potentially risky methods.
    """
    
    # HTTP methods to test
    METHODS_TO_TEST = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "OPTIONS",
        "HEAD",
        "TRACE",
    ]
    
    # Methods that are considered potentially risky
    RISKY_METHODS = {"PUT", "DELETE", "PATCH", "TRACE"}
    
    # Methods that typically require a request body
    BODY_METHODS = {"POST", "PUT", "PATCH"}
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the HTTPMethodScanner module.
        
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
        Discover supported HTTP methods for the target.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing HTTP method findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Determine which protocols to try
            protocols = self.http_probe.determine_protocols(target)
            
            # Try each protocol until one succeeds
            supported_methods = None
            final_url = None
            for protocol in protocols:
                try:
                    result = await self._test_methods(target, protocol)
                    if result:
                        supported_methods = result["supported_methods"]
                        final_url = result["final_url"]
                        break
                except Exception:
                    # Try next protocol
                    continue
            
            if supported_methods is not None:
                # Create findings from supported methods
                findings.extend(self._create_findings(supported_methods, final_url or target.normalized_target))
                status = Status.COMPLETED
            else:
                # All protocols failed
                error_finding = Finding(
                    title="HTTP Method Scan Failed",
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
                title="HTTP Method Scan Failed",
                description=f"HTTP method scan encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="HTTPMethodScanner",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    async def _test_methods(self, target: Target, protocol: str) -> dict | None:
        """
        Test all HTTP methods against the target.
        
        Args:
            target: The target to test
            protocol: The protocol to use ("http" or "https")
            
        Returns:
            Dictionary with supported methods and final URL, or None if failed
        """
        # Build URL
        normalized = target.normalized_target
        if not normalized.startswith(("http://", "https://")):
            url = f"{protocol}://{normalized}"
        else:
            # Replace protocol if specified
            if normalized.startswith("http://"):
                url = f"{protocol}://" + normalized[7:]
            else:
                url = f"{protocol}://" + normalized[8:]
        
        supported_methods = []
        
        # Test each method sequentially
        for method in self.METHODS_TO_TEST:
            try:
                is_supported = await self._test_single_method(url, method)
                if is_supported:
                    supported_methods.append(method)
            except Exception:
                # Continue testing other methods even if one fails
                continue
        
        if supported_methods:
            return {
                "supported_methods": supported_methods,
                "final_url": url
            }
        
        return None
    
    async def _test_single_method(self, url: str, method: str) -> bool:
        """
        Test a single HTTP method.
        
        Args:
            url: The target URL
            method: The HTTP method to test
            
        Returns:
            True if method is supported (not 405), False otherwise
        """
        # Prepare request
        kwargs = {
            "timeout": self.timeout,
            "follow_redirects": True
        }
        
        # Add empty body for methods that typically require it
        if method in self.BODY_METHODS:
            kwargs["json"] = {}
        
        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.request(method, url, **kwargs)
            
            # Method is supported if not 405 Method Not Allowed
            return response.status_code != 405
    
    def _create_findings(self, supported_methods: list[str], target: str) -> list[Finding]:
        """
        Create findings from supported HTTP methods.
        
        Args:
            supported_methods: List of supported HTTP methods
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Overall finding about supported methods
        methods_str = ", ".join(supported_methods)
        overall_finding = Finding(
            title="HTTP Methods Supported",
            description=f"The target supports the following HTTP methods: {methods_str}",
            severity=Severity.INFO,
            category=Category.WEB_SECURITY,
            affected_target=target,
            recommendation="Review supported methods and ensure only necessary methods are enabled."
        )
        findings.append(overall_finding)
        
        # Identify risky methods
        risky_supported = [m for m in supported_methods if m in self.RISKY_METHODS]
        if risky_supported:
            risky_str = ", ".join(risky_supported)
            risky_finding = Finding(
                title="Potentially Risky HTTP Methods Enabled",
                description=f"The target supports potentially risky HTTP methods: {risky_str}. These methods could be used for data modification or information disclosure.",
                severity=Severity.MEDIUM,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Consider disabling risky HTTP methods if they are not required for the application's functionality."
            )
            findings.append(risky_finding)
        
        # TRACE method is particularly risky (potential for XST attacks)
        if "TRACE" in supported_methods:
            trace_finding = Finding(
                title="TRACE Method Enabled",
                description="The TRACE HTTP method is enabled. This method can potentially be used for Cross-Site Tracing (XST) attacks.",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Disable the TRACE method on the web server to prevent potential XST attacks."
            )
            findings.append(trace_finding)
        
        return findings
