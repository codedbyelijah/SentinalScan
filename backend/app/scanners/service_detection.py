import asyncio
import socket
import time
from typing import Optional

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.scan_module import ScanModule


class ServiceDetection(ScanModule):
    """
    Asynchronous service detection module.
    
    Identifies services running on open ports using a hybrid approach:
    port-based detection with banner grabbing confirmation.
    """
    
    # Common service port mappings
    COMMON_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
    }
    
    def __init__(
        self,
        open_ports: list[int],
        banner_timeout: float = 2.0
    ):
        """
        Initialize the ServiceDetection module.
        
        Args:
            open_ports: List of port numbers to analyze (should be open ports from PortScanner)
            banner_timeout: Timeout in seconds for banner grabbing attempts. Default: 2.0
            
        Raises:
            ValueError: If open_ports is empty or contains invalid port numbers
        """
        if not open_ports:
            raise ValueError("open_ports cannot be empty")
        
        for port in open_ports:
            if port < 1 or port > 65535:
                raise ValueError(f"Invalid port number: {port}. Must be between 1 and 65535")
        
        self.open_ports = open_ports
        self.banner_timeout = banner_timeout
    
    async def scan(self, target: Target) -> ScanResult:
        """
        Detect services running on the target's open ports.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing detected service findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Grab banners from all open ports concurrently
            port_banners = await self._grab_banners(target)
            
            # Detect services using hybrid approach
            detected_services = self._detect_services(port_banners)
            
            # Create findings for each detected service
            for port, service_info in detected_services.items():
                service_name = service_info["service"]
                banner = service_info.get("banner", "")
                detection_method = service_info["method"]
                
                if service_name == "Unknown":
                    # Unknown service - informational finding
                    title = f"Unknown Service on Port {port}"
                    description = f"Unknown service detected on port {port}"
                    if banner:
                        description += f". Banner: {banner[:100]}..."
                    severity = Severity.INFO
                else:
                    # Known service - informational finding
                    title = f"Service Detected: {service_name} on Port {port}"
                    description = f"{service_name} service detected on port {port} ({detection_method})"
                    if banner:
                        description += f". Banner: {banner[:100]}..."
                    severity = Severity.INFO
                
                finding = Finding(
                    title=title,
                    description=description,
                    severity=severity,
                    category=Category.RECONNAISSANCE,
                    affected_target=f"{target.normalized_target}:{port}",
                    recommendation=f"Review {service_name if service_name != 'Unknown' else 'this service'} configuration and ensure it is properly secured."
                )
                findings.append(finding)
            
            status = Status.COMPLETED
            
        except Exception as e:
            # Handle unexpected errors gracefully
            status = Status.FAILED
            error_finding = Finding(
                title="Service Detection Failed",
                description=f"Service detection encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.RECONNAISSANCE,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="ServiceDetection",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    async def _grab_banners(self, target: Target) -> dict[int, str]:
        """
        Grab banners from all open ports concurrently.
        
        Args:
            target: The target to grab banners from
            
        Returns:
            Dictionary mapping port numbers to banner strings (empty string if no banner)
        """
        tasks = []
        for port in self.open_ports:
            task = self._grab_banner(target, port)
            tasks.append(task)
        
        # Execute all banner grabs concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Build port-to-banner mapping
        port_banners = {}
        for port, result in zip(self.open_ports, results):
            if isinstance(result, str):
                port_banners[port] = result
            else:
                port_banners[port] = ""
        
        return port_banners
    
    async def _grab_banner(self, target: Target, port: int) -> str:
        """
        Grab banner from a single port.
        
        Args:
            target: The target to grab banner from
            port: The port number to grab banner from
            
        Returns:
            Banner string if available, empty string otherwise
        """
        try:
            # Run socket connection in a thread pool to avoid blocking
            loop = asyncio.get_running_loop()
            
            def connect_and_grab() -> str:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.banner_timeout)
                    sock.connect((target.normalized_target, port))
                    
                    # Try to receive banner
                    sock.settimeout(1.0)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    return banner
                except (socket.error, OSError, UnicodeDecodeError):
                    return ""
                finally:
                    if sock:
                        sock.close()
            
            # Run the blocking socket operation in a thread pool
            return await loop.run_in_executor(None, connect_and_grab)
            
        except Exception:
            # Handle any unexpected errors during banner grab
            return ""
    
    def _detect_services(self, port_banners: dict[int, str]) -> dict[int, dict]:
        """
        Detect services using hybrid port/banner approach.
        
        Args:
            port_banners: Dictionary mapping port numbers to banner strings
            
        Returns:
            Dictionary mapping port numbers to service info dicts with keys:
            - service: detected service name
            - method: detection method ("port-based", "banner-based", or "hybrid")
            - banner: banner string if available
        """
        detected = {}
        
        for port, banner in port_banners.items():
            # Start with port-based guess
            port_guess = self.COMMON_SERVICES.get(port, "Unknown")
            
            # Try to identify from banner
            banner_service = self._identify_from_banner(banner)
            
            if banner_service:
                # Banner provided identification - trust it
                detected[port] = {
                    "service": banner_service,
                    "method": "banner-based",
                    "banner": banner
                }
            elif port_guess != "Unknown":
                # No banner but port is known
                detected[port] = {
                    "service": port_guess,
                    "method": "port-based",
                    "banner": banner
                }
            else:
                # Unknown port and no banner
                detected[port] = {
                    "service": "Unknown",
                    "method": "unknown",
                    "banner": banner
                }
        
        return detected
    
    def _identify_from_banner(self, banner: str) -> Optional[str]:
        """
        Identify service from banner string.
        
        Args:
            banner: The banner string to analyze
            
        Returns:
            Service name if identified, None otherwise
        """
        if not banner:
            return None
        
        banner_lower = banner.lower()
        
        # Common banner patterns
        if "ssh" in banner_lower or "openssh" in banner_lower:
            return "SSH"
        elif "ftp" in banner_lower or "file transfer protocol" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower or "postfix" in banner_lower or "sendmail" in banner_lower:
            return "SMTP"
        elif "pop3" in banner_lower or "pop" in banner_lower:
            return "POP3"
        elif "imap" in banner_lower:
            return "IMAP"
        elif "http" in banner_lower or "apache" in banner_lower or "nginx" in banner_lower:
            return "HTTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "postgresql" in banner_lower or "postgres" in banner_lower:
            return "PostgreSQL"
        elif "redis" in banner_lower:
            return "Redis"
        
        return None
