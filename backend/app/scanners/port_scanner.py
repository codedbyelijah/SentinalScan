import asyncio
import socket
import time

from app.models.enums import Category, Severity, Status
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.scanners.scan_module import ScanModule


class PortScanner(ScanModule):
    """
    Asynchronous TCP port scanning module.
    
    Scans a target's ports concurrently using asyncio and Python's socket library.
    Detects open ports and returns findings for each discovered open port.
    """
    
    def __init__(
        self,
        start_port: int = 1,
        end_port: int = 1024,
        timeout: float = 1.0
    ):
        """
        Initialize the PortScanner.
        
        Args:
            start_port: First port number to scan (inclusive). Default: 1
            end_port: Last port number to scan (inclusive). Default: 1024
            timeout: Connection timeout in seconds per port. Default: 1.0
            
        Raises:
            ValueError: If port range or timeout values are invalid
        """
        if start_port < 1 or start_port > 65535:
            raise ValueError(f"start_port must be between 1 and 65535, got {start_port}")
        if end_port < 1 or end_port > 65535:
            raise ValueError(f"end_port must be between 1 and 65535, got {end_port}")
        if start_port > end_port:
            raise ValueError(f"start_port ({start_port}) must be less than or equal to end_port ({end_port})")
        if timeout <= 0:
            raise ValueError(f"timeout must be positive, got {timeout}")
        
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
    
    async def scan(self, target: Target) -> ScanResult:
        """
        Scan the target for open TCP ports.
        
        Args:
            target: The validated Target model to scan
            
        Returns:
            ScanResult containing open port findings
        """
        start_time = time.time()
        findings: list[Finding] = []
        
        try:
            # Scan ports concurrently
            open_ports = await self._scan_ports(target)
            
            # Create a finding for each open port
            for port in open_ports:
                finding = Finding(
                    title=f"Open TCP Port: {port}",
                    description=f"Port {port} is open and accepting TCP connections on {target.normalized_target}",
                    severity=Severity.INFO,
                    category=Category.PORT_SCANNING,
                    affected_target=f"{target.normalized_target}:{port}",
                    recommendation="Review whether this port should be exposed. If not required, consider closing it or restricting access."
                )
                findings.append(finding)
            
            status = Status.COMPLETED
            
        except Exception as e:
            # Handle unexpected errors gracefully
            status = Status.FAILED
            error_finding = Finding(
                title="Port Scan Failed",
                description=f"Port scanning encountered an unexpected error: {str(e)}",
                severity=Severity.HIGH,
                category=Category.PORT_SCANNING,
                affected_target=target.normalized_target,
                recommendation="Check network connectivity and target accessibility."
            )
            findings.append(error_finding)
        
        execution_time = time.time() - start_time
        
        return ScanResult(
            module_name="PortScanner",
            status=status,
            execution_time=execution_time,
            findings=findings
        )
    
    async def _scan_ports(self, target: Target) -> list[int]:
        """
        Scan all ports in the configured range concurrently.
        
        Args:
            target: The target to scan
            
        Returns:
            List of open port numbers
        """
        tasks = []
        # Clamp end_port to maximum valid port
        max_port = min(self.end_port, 65535)
        for port in range(self.start_port, max_port + 1):
            task = self._check_port(target, port)
            tasks.append(task)
        
        # Execute all port checks concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter successful connections (True results)
        open_ports = []
        max_port = min(self.end_port, 65535)
        for port, result in zip(range(self.start_port, max_port + 1), results):
            if result is True:
                open_ports.append(port)
        
        return open_ports
    
    async def _check_port(self, target: Target, port: int) -> bool:
        """
        Check if a single port is open on the target.
        
        Args:
            target: The target to check
            port: The port number to check
            
        Returns:
            True if the port is open, False otherwise
        """
        try:
            # Run socket connection in a thread pool to avoid blocking
            loop = asyncio.get_running_loop()
            
            def connect() -> bool:
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((target.normalized_target, port))
                    return result == 0
                except (socket.error, OSError):
                    return False
                finally:
                    if sock:
                        sock.close()
            
            # Run the blocking socket operation in a thread pool
            return await loop.run_in_executor(None, connect)
            
        except Exception:
            # Handle any unexpected errors during port check
            return False
