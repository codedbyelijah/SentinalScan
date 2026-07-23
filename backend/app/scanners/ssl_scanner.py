import datetime
import socket
import ssl
import time
from urllib.parse import urlparse

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.scan_module import ScanModule


class SSLScanner(ScanModule):
    """
    Asynchronous SSL/TLS certificate analysis module.
    
    Retrieves and analyzes SSL/TLS certificates for HTTPS targets.
    Detects expired certificates, near-expiring certificates, and deprecated TLS versions.
    """
    
    # Days threshold for "nearing expiration"
    EXPIRATION_WARNING_DAYS = 30
    
    # Deprecated TLS versions
    DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.1"}
    
    # Default SSL port
    DEFAULT_SSL_PORT = 443
    
    def __init__(self, timeout: float = 10.0):
        """
        Initialize the SSLScanner module.
        
        Args:
            timeout: Connection timeout in seconds. Default: 10.0
            
        Raises:
            ValueError: If timeout is not positive
        """
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        
        self.timeout = timeout
    
    async def scan(self, target: Target) -> ScanResult:
        """
        Analyze SSL/TLS certificate for the target.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing SSL/TLS certificate findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Check if target uses HTTPS
            if not self._is_https_target(target):
                error_finding = Finding(
                    title="SSL/TLS Scan Failed",
                    description=f"Target {target.normalized_target} does not use HTTPS. SSL/TLS analysis requires HTTPS.",
                    severity=Severity.HIGH,
                    category=Category.WEB_SECURITY,
                    affected_target=target.normalized_target,
                    recommendation="Ensure the target uses HTTPS for SSL/TLS certificate analysis."
                )
                findings.append(error_finding)
                status = Status.FAILED
            else:
                # Extract hostname and port from target
                hostname, port = self._extract_hostname_and_port(target)
                
                # Retrieve certificate information
                cert_info = self._get_certificate_info(hostname, port)
                
                if cert_info:
                    # Create findings from certificate information
                    findings.extend(self._create_findings(cert_info, target.normalized_target))
                    status = Status.COMPLETED
                else:
                    # Certificate retrieval failed
                    error_finding = Finding(
                        title="SSL/TLS Scan Failed",
                        description=f"Unable to retrieve SSL/TLS certificate for {target.normalized_target}",
                        severity=Severity.HIGH,
                        category=Category.WEB_SECURITY,
                        affected_target=target.normalized_target,
                        recommendation="Verify the target is accessible and has a valid SSL/TLS certificate."
                    )
                    findings.append(error_finding)
                    status = Status.FAILED
            
        except Exception as e:
            # Handle unexpected errors gracefully
            status = Status.FAILED
            error_finding = Finding(
                title="SSL/TLS Scan Failed",
                description=f"SSL/TLS scan encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="SSLScanner",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    def _is_https_target(self, target: Target) -> bool:
        """
        Check if the target uses HTTPS.
        
        Args:
            target: The target to check
            
        Returns:
            True if target uses HTTPS, False otherwise
        """
        normalized = target.normalized_target.lower()
        return normalized.startswith("https://")
    
    def _extract_hostname_and_port(self, target: Target) -> tuple[str, int]:
        """
        Extract hostname and port from target URL.
        
        Args:
            target: The target to extract hostname and port from
            
        Returns:
            Tuple of (hostname, port)
        """
        normalized = target.normalized_target
        parsed = urlparse(normalized)
        hostname = parsed.hostname or parsed.netloc
        port = parsed.port if parsed.port else self.DEFAULT_SSL_PORT
        return hostname, port
    
    def _get_certificate_info(self, hostname: str, port: int = 443) -> dict | None:
        """
        Retrieve SSL/TLS certificate information.
        
        Args:
            hostname: The hostname to connect to
            port: The port to connect to. Default: 443
            
        Returns:
            Dictionary with certificate information, or None if failed
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Establish SSL connection
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                    # Get certificate
                    cert = ssl_sock.getpeercert()
                    
                    # Get TLS version
                    tls_version = ssl_sock.version()
                    
                    # Extract certificate information
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    valid_from = cert.get("notBefore")
                    valid_to = cert.get("notAfter")
                    
                    # Parse dates
                    valid_from_date = self._parse_ssl_date(valid_from) if valid_from else None
                    valid_to_date = self._parse_ssl_date(valid_to) if valid_to else None
                    
                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "valid_from": valid_from_date,
                        "valid_to": valid_to_date,
                        "tls_version": tls_version
                    }
        except Exception:
            return None
    
    def _parse_ssl_date(self, date_str: str) -> datetime.datetime:
        """
        Parse SSL certificate date string.
        
        Args:
            date_str: Date string in SSL format (e.g., "May 25 12:00:00 2024 GMT")
            
        Returns:
            datetime object with UTC timezone
        """
        naive_date = datetime.datetime.strptime(date_str, "%b %d %H:%M:%S %Y GMT")
        return naive_date.replace(tzinfo=datetime.timezone.utc)
    
    def _create_findings(self, cert_info: dict, target: str) -> list[Finding]:
        """
        Create findings from certificate information.
        
        Args:
            cert_info: Dictionary with certificate information
            target: The target URL
            
        Returns:
            List of Finding objects
        """
        findings = []
        
        # Certificate information finding
        subject = cert_info["subject"]
        issuer = cert_info["issuer"]
        valid_from = cert_info["valid_from"]
        valid_to = cert_info["valid_to"]
        tls_version = cert_info["tls_version"]
        
        subject_cn = subject.get("commonName", "N/A")
        issuer_cn = issuer.get("commonName", "N/A")
        
        valid_from_str = valid_from.strftime('%Y-%m-%d') if valid_from else "N/A"
        valid_to_str = valid_to.strftime('%Y-%m-%d') if valid_to else "N/A"
        
        cert_info_finding = Finding(
            title="SSL/TLS Certificate Information",
            description=f"Certificate issued to: {subject_cn}. Issuer: {issuer_cn}. Valid from: {valid_from_str} to: {valid_to_str}. TLS Version: {tls_version}",
            severity=Severity.INFO,
            category=Category.WEB_SECURITY,
            affected_target=target,
            recommendation="Review certificate information for accuracy and security."
        )
        findings.append(cert_info_finding)
        
        # Check for expired certificate
        now = datetime.datetime.now(datetime.timezone.utc)
        if valid_to and valid_to < now:
            valid_to_str = valid_to.strftime('%Y-%m-%d')
            expired_finding = Finding(
                title="Expired SSL/TLS Certificate",
                description=f"The SSL/TLS certificate expired on {valid_to_str}",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Renew the SSL/TLS certificate immediately. Expired certificates cause security warnings and connection failures."
            )
            findings.append(expired_finding)
        
        # Check for certificate nearing expiration
        if valid_to:
            days_until_expiry = (valid_to - now).days
            if 0 < days_until_expiry <= self.EXPIRATION_WARNING_DAYS:
                near_expiry_finding = Finding(
                    title="SSL/TLS Certificate Nearing Expiration",
                    description=f"The SSL/TLS certificate will expire in {days_until_expiry} days. Renew the certificate before it expires to avoid service disruption.",
                    severity=Severity.MEDIUM,
                    category=Category.WEB_SECURITY,
                    affected_target=target,
                    recommendation=f"Renew the SSL/TLS certificate within the next {days_until_expiry} days."
                )
                findings.append(near_expiry_finding)
        
        # Check for deprecated TLS version
        if tls_version in self.DEPRECATED_TLS_VERSIONS:
            deprecated_tls_finding = Finding(
                title="Deprecated TLS Version Detected",
                description=f"The server uses deprecated TLS version: {tls_version}. TLS 1.0 and 1.1 are deprecated and have known vulnerabilities.",
                severity=Severity.HIGH,
                category=Category.WEB_SECURITY,
                affected_target=target,
                recommendation="Upgrade to TLS 1.2 or TLS 1.3 for improved security."
            )
            findings.append(deprecated_tls_finding)
        
        return findings
