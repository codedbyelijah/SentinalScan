import time

import httpx

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.scan_module import ScanModule


class HttpProbe(ScanModule):
    """
    Asynchronous HTTP probing module.
    
    Gathers basic information from web services including final URL,
    status code, response time, redirect chain, server header, and response headers.
    """
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the HttpProbe module.
        
        Args:
            timeout: Request timeout in seconds. Default: 10.0
            
        Raises:
            ValueError: If timeout is not positive
        """
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        
        self.timeout = timeout
    
    async def scan(self, target: Target) -> ScanResult:
        """
        Probe the target for HTTP information.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing HTTP probe findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Determine which protocols to try
            protocols = self.determine_protocols(target)
            
            # Try each protocol until one succeeds
            result = None
            for protocol in protocols:
                try:
                    result = await self.probe_http(target, protocol)
                    if result:
                        break
                except Exception:
                    # Try next protocol
                    continue
            
            if result:
                # Create findings from the successful probe
                findings.extend(self._create_findings(target, result))
                status = Status.COMPLETED
            else:
                # All protocols failed
                error_finding = Finding(
                    title="HTTP Probe Failed",
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
                title="HTTP Probe Failed",
                description=f"HTTP probe encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="HttpProbe",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    def determine_protocols(self, target: Target) -> list[str]:
        """
        Determine which protocols to try based on the target.
        
        Args:
            target: The target to analyze
            
        Returns:
            List of protocols to try (e.g., ["https", "http"])
        """
        normalized = target.normalized_target.lower()
        
        if normalized.startswith("https://"):
            return ["https"]
        elif normalized.startswith("http://"):
            return ["http"]
        else:
            # Try HTTPS first, then HTTP
            return ["https", "http"]
    
    async def probe_http(self, target: Target, protocol: str) -> dict | None:
        """
        Perform HTTP probe with the specified protocol.
        
        Args:
            target: The target to probe
            protocol: The protocol to use ("http" or "https")
            
        Returns:
            Dictionary containing probe results, or None if failed
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
        
        # Create HTTP client with redirect tracking
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            response = await client.get(url)
            
            # Build redirect chain
            redirect_chain = []
            for history in response.history:
                redirect_chain.append({
                    "url": str(history.request.url),
                    "status": history.status_code
                })
            
            # Add final URL to chain
            redirect_chain.append({
                "url": str(response.url),
                "status": response.status_code
            })
            
            return {
                "final_url": str(response.url),
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "redirect_chain": redirect_chain,
                "server_header": response.headers.get("Server", ""),
                "response_headers": dict(response.headers),
                "response_body": response.text,
                "cookies": dict(response.cookies)
            }
    
    def _create_findings(self, target: Target, result: dict) -> list[Finding]:
        """
        Create findings from HTTP probe results.
        
        Args:
            target: The target that was probed
            result: The probe results dictionary
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Basic HTTP info finding
        basic_info = Finding(
            title="HTTP Service Detected",
            description=f"HTTP service detected at {result['final_url']}. Status code: {result['status_code']}. Response time: {result['response_time']:.3f}s.",
            severity=Severity.INFO,
            category=Category.WEB_SECURITY,
            affected_target=result['final_url'],
            recommendation="Review HTTP service configuration and ensure proper security measures are in place."
        )
        findings.append(basic_info)
        
        # Redirect chain finding (if redirects exist)
        if len(result['redirect_chain']) > 1:
            redirect_urls = " -> ".join([f"{r['url']} ({r['status']})" for r in result['redirect_chain']])
            redirect_finding = Finding(
                title="HTTP Redirect Chain Detected",
                description=f"Redirect chain detected: {redirect_urls}",
                severity=Severity.INFO,
                category=Category.WEB_SECURITY,
                affected_target=result['final_url'],
                recommendation="Review redirect chain for security implications and ensure redirects are intentional."
            )
            findings.append(redirect_finding)
        
        # Server header finding
        if result['server_header']:
            server_finding = Finding(
                title="Server Header Information",
                description=f"Server header: {result['server_header']}",
                severity=Severity.INFO,
                category=Category.WEB_SECURITY,
                affected_target=result['final_url'],
                recommendation="Consider obscuring server information to reduce information disclosure."
            )
            findings.append(server_finding)
        
        # Response headers finding
        headers_text = ", ".join([f"{k}: {v}" for k, v in result['response_headers'].items()])
        headers_finding = Finding(
            title="HTTP Response Headers",
            description=f"Response headers: {headers_text}",
            severity=Severity.INFO,
            category=Category.WEB_SECURITY,
            affected_target=result['final_url'],
            recommendation="Review response headers for security configuration (e.g., security headers, CORS policies)."
        )
        findings.append(headers_finding)
        
        return findings
