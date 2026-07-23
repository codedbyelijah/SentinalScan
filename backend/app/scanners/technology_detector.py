import re
import time

from bs4 import BeautifulSoup

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.http_probe import HttpProbe
from app.scanners.scan_module import ScanModule


class TechnologyDetector(ScanModule):
    """
    Asynchronous technology detection module.
    
    Identifies technologies powering web applications by analyzing
    HTTP response headers, HTML source code, and response cookies.
    """
    
    # Technology detection rules
    HEADER_PATTERNS = {
        "Web Server": {
            "nginx": re.compile(r"nginx", re.IGNORECASE),
            "Apache": re.compile(r"Apache", re.IGNORECASE),
            "IIS": re.compile(r"IIS", re.IGNORECASE),
            "LiteSpeed": re.compile(r"LiteSpeed", re.IGNORECASE),
            "Caddy": re.compile(r"Caddy", re.IGNORECASE),
        },
        "Programming Language": {
            "PHP": re.compile(r"PHP", re.IGNORECASE),
            "Python": re.compile(r"Python", re.IGNORECASE),
            "Ruby": re.compile(r"Ruby", re.IGNORECASE),
            "Java": re.compile(r"Java", re.IGNORECASE),
            "Node.js": re.compile(r"Node", re.IGNORECASE),
        },
        "Framework": {
            "ASP.NET": re.compile(r"ASP\.NET", re.IGNORECASE),
            "Express": re.compile(r"Express", re.IGNORECASE),
            "Django": re.compile(r"Django", re.IGNORECASE),
            "Flask": re.compile(r"Flask", re.IGNORECASE),
            "Rails": re.compile(r"Rails", re.IGNORECASE),
            "Laravel": re.compile(r"Laravel", re.IGNORECASE),
            "Spring": re.compile(r"Spring", re.IGNORECASE),
        },
    }
    
    HTML_PATTERNS = {
        "CMS": {
            "WordPress": re.compile(r"wp-content|wordpress", re.IGNORECASE),
            "Drupal": re.compile(r"drupal", re.IGNORECASE),
            "Joomla": re.compile(r"joomla", re.IGNORECASE),
            "Magento": re.compile(r"magento", re.IGNORECASE),
        },
        "Framework": {
            "React": re.compile(r"react|reactjs", re.IGNORECASE),
            "Vue": re.compile(r"vue\.js|vuejs", re.IGNORECASE),
            "Angular": re.compile(r"angular", re.IGNORECASE),
            "jQuery": re.compile(r"jquery", re.IGNORECASE),
            "Bootstrap": re.compile(r"bootstrap", re.IGNORECASE),
            "Tailwind": re.compile(r"tailwind", re.IGNORECASE),
        },
    }
    
    COOKIE_PATTERNS = {
        "Programming Language": {
            "PHP": re.compile(r"PHPSESSID", re.IGNORECASE),
            "Java": re.compile(r"JSESSIONID", re.IGNORECASE),
            "ASP.NET": re.compile(r"ASP\.NET_SessionId", re.IGNORECASE),
            "Python": re.compile(r"sessionid", re.IGNORECASE),
        },
    }
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the TechnologyDetector module.
        
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
        Detect technologies for the target.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing technology detection findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Determine which protocols to try
            protocols = self.http_probe.determine_protocols(target)
            
            # Try each protocol until one succeeds
            response_data = None
            for protocol in protocols:
                try:
                    result = await self.http_probe.probe_http(target, protocol)
                    if result:
                        response_data = result
                        break
                except Exception:
                    # Try next protocol
                    continue
            
            if response_data:
                # Extract response data
                headers = response_data.get("response_headers", {})
                body = response_data.get("response_body", "")
                cookies = response_data.get("cookies", {})
                
                # Detect technologies
                detected = {}
                
                # Analyze headers
                header_techs = self._analyze_headers(headers)
                for category, techs in header_techs.items():
                    if category not in detected:
                        detected[category] = []
                    detected[category].extend(techs)
                
                # Analyze HTML
                html_techs = self._analyze_html(body)
                for category, techs in html_techs.items():
                    if category not in detected:
                        detected[category] = []
                    detected[category].extend(techs)
                
                # Analyze cookies
                cookie_techs = self._analyze_cookies(cookies)
                for category, techs in cookie_techs.items():
                    if category not in detected:
                        detected[category] = []
                    detected[category].extend(techs)
                
                # Create findings from detected technologies
                findings.extend(self._create_findings(detected, target.normalized_target))
                status = Status.COMPLETED
            else:
                # All protocols failed
                error_finding = Finding(
                    title="Technology Detection Failed",
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
                title="Technology Detection Failed",
                description=f"Technology detection encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="TechnologyDetector",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    def _analyze_headers(self, headers: dict) -> dict[str, list[str]]:
        """
        Analyze HTTP response headers for technology indicators.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Dictionary mapping categories to detected technologies
        """
        detected = {}
        
        for category, patterns in self.HEADER_PATTERNS.items():
            for tech_name, pattern in patterns.items():
                for header_name, header_value in headers.items():
                    if pattern.search(str(header_value)):
                        if category not in detected:
                            detected[category] = []
                        if tech_name not in detected[category]:
                            detected[category].append(tech_name)
        
        return detected
    
    def _analyze_html(self, html: str) -> dict[str, list[str]]:
        """
        Analyze HTML source code for technology fingerprints.
        
        Args:
            html: HTML source code
            
        Returns:
            Dictionary mapping categories to detected technologies
        """
        detected = {}
        
        if not html:
            return detected
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Check meta tags
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and meta_generator.get('content'):
                content = meta_generator['content'].lower()
                for category, patterns in self.HTML_PATTERNS.items():
                    for tech_name, pattern in patterns.items():
                        if pattern.search(content):
                            if category not in detected:
                                detected[category] = []
                            if tech_name not in detected[category]:
                                detected[category].append(tech_name)
            
            # Check script tags
            for script in soup.find_all('script'):
                src = script.get('src', '').lower()
                content = script.string or ''
                for category, patterns in self.HTML_PATTERNS.items():
                    for tech_name, pattern in patterns.items():
                        if pattern.search(src) or pattern.search(content):
                            if category not in detected:
                                detected[category] = []
                            if tech_name not in detected[category]:
                                detected[category].append(tech_name)
            
            # Check all text content
            text = soup.get_text().lower()
            for category, patterns in self.HTML_PATTERNS.items():
                for tech_name, pattern in patterns.items():
                    if pattern.search(text):
                        if category not in detected:
                            detected[category] = []
                        if tech_name not in detected[category]:
                            detected[category].append(tech_name)
        
        except Exception:
            # If HTML parsing fails, return empty results
            pass
        
        return detected
    
    def _analyze_cookies(self, cookies: dict) -> dict[str, list[str]]:
        """
        Analyze response cookies for technology indicators.
        
        Args:
            cookies: Response cookies
            
        Returns:
            Dictionary mapping categories to detected technologies
        """
        detected = {}
        
        for category, patterns in self.COOKIE_PATTERNS.items():
            for tech_name, pattern in patterns.items():
                for cookie_name in cookies.keys():
                    if pattern.search(cookie_name):
                        if category not in detected:
                            detected[category] = []
                        if tech_name not in detected[category]:
                            detected[category].append(tech_name)
        
        return detected
    
    def _create_findings(self, detected: dict[str, list[str]], target: str) -> list[Finding]:
        """
        Create findings from detected technologies.
        
        Args:
            detected: Dictionary mapping categories to detected technologies
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        if not detected:
            # No technologies detected
            no_tech_finding = Finding(
                title="No Technologies Detected",
                description="No common technologies were detected in the HTTP response headers, HTML source code, or cookies.",
                severity=Severity.INFO,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="The target may be using custom or uncommon technologies not covered by the detection rules."
            )
            findings.append(no_tech_finding)
        else:
            # Create findings for each category
            for category, technologies in detected.items():
                if technologies:
                    techs_str = ", ".join(technologies)
                    tech_finding = Finding(
                        title=f"Detected {category}",
                        description=f"The following {category.lower()} were detected: {techs_str}",
                        severity=Severity.INFO,
                        category=Category.WEB_SECURITY,
                        affected_target=target,
                        recommendation=f"Review the detected {category.lower()} for security best practices and known vulnerabilities."
                    )
                    findings.append(tech_finding)
        
        return findings
