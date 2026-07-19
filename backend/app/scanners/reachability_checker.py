import asyncio
import platform
import re
import subprocess
import time
from typing import Literal

import httpx

from app.models.enums import TargetType
from app.models.reachability_result import ReachabilityResult
from app.models.target import Target


class ReachabilityError(Exception):
    """Raised when reachability check cannot be completed due to system errors."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ReachabilityChecker:
    """Checks if targets are reachable before scanning."""
    
    # Timeout values (in seconds)
    HTTP_TIMEOUT = 10.0
    PING_TIMEOUT = 4.0
    PING_COUNT = 2
    
    @staticmethod
    async def check(target: Target) -> ReachabilityResult:
        """
        Check if a target is reachable.
        
        Args:
            target: The validated Target model to check
            
        Returns:
            ReachabilityResult with status and response time
            
        Raises:
            ReachabilityError: If the check cannot be completed due to system errors
        """
        if target.target_type in (TargetType.URL, TargetType.DOMAIN):
            return await ReachabilityChecker._check_http(target)
        elif target.target_type in (TargetType.IPV4, TargetType.IPV6):
            return await ReachabilityChecker._check_ping(target)
        else:
            raise ReachabilityError(f"Unsupported target type: {target.target_type}")
    
    @staticmethod
    async def _check_http(target: Target) -> ReachabilityResult:
        """Check reachability using HTTP/HTTPS request."""
        url = target.normalized_target
        
        try:
            start_time = time.time()
            
            async with httpx.AsyncClient(timeout=ReachabilityChecker.HTTP_TIMEOUT) as client:
                response = await client.head(url, follow_redirects=True)
                
            elapsed_ms = (time.time() - start_time) * 1000
            
            # Consider 2xx, 3xx, and 4xx as reachable (server responded)
            # Only 5xx and network errors indicate unreachable
            if response.status_code < 500:
                return ReachabilityResult(
                    reachable=True,
                    response_time_ms=round(elapsed_ms, 2),
                    method_used="http"
                )
            else:
                return ReachabilityResult(
                    reachable=False,
                    response_time_ms=round(elapsed_ms, 2),
                    method_used="http"
                )
                
        except httpx.TimeoutException:
            # Expected failure - target is unreachable
            return ReachabilityResult(
                reachable=False,
                response_time_ms=None,
                method_used="http"
            )
        except httpx.ConnectError:
            # Expected failure - target is unreachable
            return ReachabilityResult(
                reachable=False,
                response_time_ms=None,
                method_used="http"
            )
        except httpx.HTTPStatusError:
            # Expected failure - server responded with error
            return ReachabilityResult(
                reachable=False,
                response_time_ms=None,
                method_used="http"
            )
        except Exception as e:
            # Unexpected failure - raise error
            raise ReachabilityError(f"HTTP check failed: {str(e)}")
    
    @staticmethod
    async def _check_ping(target: Target) -> ReachabilityResult:
        """Check reachability using ICMP ping."""
        system = platform.system().lower()
        
        # Build ping command based on platform
        if system == "windows":
            cmd = ["ping", "-n", str(ReachabilityChecker.PING_COUNT), "-w", str(int(ReachabilityChecker.PING_TIMEOUT * 1000)), target.normalized_target]
        elif system == "linux":
            cmd = ["ping", "-c", str(ReachabilityChecker.PING_COUNT), "-W", str(int(ReachabilityChecker.PING_TIMEOUT)), target.normalized_target]
        elif system == "darwin":  # macOS
            cmd = ["ping", "-c", str(ReachabilityChecker.PING_COUNT), "-W", str(int(ReachabilityChecker.PING_TIMEOUT * 1000)), target.normalized_target]
        else:
            raise ReachabilityError(f"Unsupported platform: {system}")
        
        try:
            # Run ping command asynchronously
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=ReachabilityChecker.PING_TIMEOUT + 2
            )
            
            output = stdout.decode('utf-8', errors='ignore')
            
            if process.returncode == 0:
                # Parse response time from ping output
                response_time = ReachabilityChecker._parse_ping_time(output, system)
                return ReachabilityResult(
                    reachable=True,
                    response_time_ms=response_time,
                    method_used="ping"
                )
            else:
                # Expected failure - host unreachable
                return ReachabilityResult(
                    reachable=False,
                    response_time_ms=None,
                    method_used="ping"
                )
                
        except asyncio.TimeoutError:
            # Expected failure - timeout
            return ReachabilityResult(
                reachable=False,
                response_time_ms=None,
                method_used="ping"
            )
        except FileNotFoundError:
            # Unexpected failure - ping command not found
            raise ReachabilityError("ping command not found. Please ensure ping is installed and accessible.")
        except PermissionError:
            # Unexpected failure - permission denied
            raise ReachabilityError("Permission denied when executing ping command.")
        except Exception as e:
            # Unexpected failure
            raise ReachabilityError(f"Ping check failed: {str(e)}")
    
    @staticmethod
    def _parse_ping_time(output: str, system: str) -> float | None:
        """Parse response time from ping output."""
        try:
            if system == "windows":
                # Windows: "Reply from 192.168.1.1: bytes=32 time=1ms TTL=64"
                match = re.search(r'time=(\d+)ms', output)
                if match:
                    return float(match.group(1))
            else:
                # Linux/macOS: "64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=0.123 ms"
                match = re.search(r'time=([\d.]+)\s*ms', output)
                if match:
                    return float(match.group(1))
            
            # If no match found, try to extract average from summary
            if system == "linux":
                match = re.search(r'rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms', output)
                if match:
                    return float(match.group(2))
            
            return None
        except Exception:
            return None
