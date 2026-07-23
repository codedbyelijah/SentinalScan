import asyncio
import time
from urllib.parse import urljoin

import httpx

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.http_probe import HttpProbe
from app.scanners.scan_module import ScanModule


class ContentDiscovery(ScanModule):
    """
    Asynchronous content discovery module.
    
    Identifies publicly accessible resources on web targets by checking
    for common resources, administrative pages, and exposed directory listings.
    """
    
    # Common resources to check
    COMMON_RESOURCES = [
        "/robots.txt",
        "/sitemap.xml",
        "/favicon.ico",
        "/security.txt",
        "/.well-known/security.txt",
    ]
    
    # Common administrative pages to check
    ADMIN_PAGES = [
        "/admin",
        "/administrator",
        "/login",
        "/dashboard",
        "/wp-admin",
        "/admin.php",
        "/administrator.php",
        "/user",
        "/users",
        "/account",
        "/accounts",
        "/panel",
        "/cpanel",
        "/webmail",
        "/console",
    ]
    
    # Common directories to check for listing
    COMMON_DIRECTORIES = [
        "/",
        "/images",
        "/uploads",
        "/files",
        "/assets",
        "/static",
        "/public",
        "/backup",
        "/backups",
        "/tmp",
        "/temp",
    ]
    
    # Indicators of directory listing in HTML response
    DIRECTORY_LISTING_INDICATORS = [
        "Index of /",
        "Directory listing for",
        "Parent Directory",
        "Name",
        "Last modified",
        "Size",
        "Description",
    ]
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the ContentDiscovery module.
        
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
        Discover content resources for the target.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing content discovery findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Determine which protocols to try
            protocols = self.http_probe.determine_protocols(target)
            
            # Use the first protocol that works
            base_protocol = protocols[0] if protocols else "https"
            
            # Build base URL
            base_url = target.normalized_target
            if not base_url.startswith(("http://", "https://")):
                base_url = f"{base_protocol}://{base_url}"
            
            # Check common resources
            resource_results = await self._check_paths_concurrently(base_url, self.COMMON_RESOURCES)
            findings.extend(self._create_resource_findings(resource_results, target.normalized_target))
            
            # Check administrative pages
            admin_results = await self._check_paths_concurrently(base_url, self.ADMIN_PAGES)
            findings.extend(self._create_admin_findings(admin_results, target.normalized_target))
            
            # Check for directory listings
            dir_results = await self._check_paths_concurrently(base_url, self.COMMON_DIRECTORIES)
            findings.extend(self._create_directory_findings(dir_results, target.normalized_target))
            
            status = Status.COMPLETED
            
        except Exception as e:
            # Handle unexpected errors gracefully
            status = Status.FAILED
            error_finding = Finding(
                title="Content Discovery Failed",
                description=f"Content discovery encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="ContentDiscovery",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    async def _check_paths_concurrently(self, base_url: str, paths: list[str]) -> list[dict]:
        """
        Check multiple paths concurrently.
        
        Args:
            base_url: The base URL to check paths against
            paths: List of paths to check
            
        Returns:
            List of dictionaries with path, status_code, accessible, and has_directory_listing
        """
        tasks = [self._check_single_path(base_url, path) for path in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and return valid results
        valid_results = []
        for result in results:
            if isinstance(result, dict):
                valid_results.append(result)
            # Silently ignore exceptions (inaccessible paths)
        
        return valid_results
    
    async def _check_single_path(self, base_url: str, path: str) -> dict | None:
        """
        Check a single path for accessibility.
        
        Args:
            base_url: The base URL
            path: The path to check
            
        Returns:
            Dictionary with path, status_code, accessible, and has_directory_listing, or None if failed
        """
        try:
            url = urljoin(base_url, path)
            
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                response = await client.get(url)
                
                # Check for directory listing
                has_directory_listing = self._detect_directory_listing(response.text)
                
                return {
                    "path": path,
                    "url": url,
                    "status_code": response.status_code,
                    "accessible": response.status_code < 400,
                    "has_directory_listing": has_directory_listing,
                    "content_length": len(response.text)
                }
        except Exception:
            # Path is inaccessible or request failed
            return None
    
    def _detect_directory_listing(self, html: str) -> bool:
        """
        Detect if HTML response contains directory listing indicators.
        
        Args:
            html: HTML response content
            
        Returns:
            True if directory listing is detected, False otherwise
        """
        if not html:
            return False
        
        html_lower = html.lower()
        for indicator in self.DIRECTORY_LISTING_INDICATORS:
            if indicator.lower() in html_lower:
                return True
        
        return False
    
    def _create_resource_findings(self, results: list[dict], target: str) -> list[Finding]:
        """
        Create findings for discovered common resources.
        
        Args:
            results: List of path check results
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        accessible_resources = [r for r in results if r.get("accessible", False)]
        
        if accessible_resources:
            resources_str = ", ".join([r["path"] for r in accessible_resources])
            finding = Finding(
                title="Common Resources Discovered",
                description=f"The following common resources are accessible: {resources_str}",
                severity=Severity.INFO,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Review these resources for sensitive information exposure."
            )
            findings.append(finding)
        
        return findings
    
    def _create_admin_findings(self, results: list[dict], target: str) -> list[Finding]:
        """
        Create findings for discovered administrative pages.
        
        Args:
            results: List of path check results
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        accessible_admin = [r for r in results if r.get("accessible", False)]
        
        if accessible_admin:
            admin_str = ", ".join([r["path"] for r in accessible_admin])
            finding = Finding(
                title="Administrative Pages Discovered",
                description=f"The following administrative pages are accessible: {admin_str}",
                severity=Severity.MEDIUM,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Ensure administrative pages are properly secured with authentication and access controls."
            )
            findings.append(finding)
        
        return findings
    
    def _create_directory_findings(self, results: list[dict], target: str) -> list[Finding]:
        """
        Create findings for exposed directory listings.
        
        Args:
            results: List of path check results
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        directory_listings = [r for r in results if r.get("has_directory_listing", False)]
        
        if directory_listings:
            dirs_str = ", ".join([r["path"] for r in directory_listings])
            finding = Finding(
                title="Exposed Directory Listings Detected",
                description=f"The following directories have exposed directory listings: {dirs_str}",
                severity=Severity.MEDIUM,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Disable directory listing to prevent information disclosure. Configure web server to return 403 or 404 for directory requests."
            )
            findings.append(finding)
        
        return findings
