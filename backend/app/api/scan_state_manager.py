import asyncio
import logging
from datetime import datetime
from typing import Any
from uuid import uuid4

from app.api.models import ScanStatus
from app.models.scan_result import ScanResult
from app.models.risk_analysis_result import RiskAnalysisResult


logger = logging.getLogger(__name__)


class ScanState:
    """Represents the state of a single scan execution."""
    
    def __init__(self, scan_id: str, target: str, total_modules: int):
        self.scan_id = scan_id
        self.target = target
        self.status = ScanStatus.PENDING
        self.start_time: datetime | None = None
        self.end_time: datetime | None = None
        self.duration_seconds: float | None = None
        self.modules_completed: list[str] = []
        self.total_modules = total_modules
        self.results: list[ScanResult] = []
        self.risk_analysis: RiskAnalysisResult | None = None
        self.error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        """Convert scan state to dictionary."""
        return {
            'scan_id': self.scan_id,
            'status': self.status.value,
            'target': self.target,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.duration_seconds,
            'modules_completed': self.modules_completed,
            'total_modules': self.total_modules,
            'error': self.error
        }


class ScanStateManager:
    """
    Manages in-memory state for scan executions.
    
    Tracks scan status, progress, and results using a dictionary keyed by scan ID.
    State is lost on application restart (aligns with runtime-only storage model).
    Thread-safe using asyncio.Lock.
    """
    
    def __init__(self):
        """Initialize the scan state manager."""
        self._scans: dict[str, ScanState] = {}
        self._lock = asyncio.Lock()
        logger.info("ScanStateManager initialized")
    
    async def create_scan(self, target: str, total_modules: int) -> str:
        """
        Create a new scan state entry.
        
        Args:
            target: The target being scanned
            total_modules: Total number of modules to execute
            
        Returns:
            The scan ID (UUID)
        """
        async with self._lock:
            scan_id = str(uuid4())
            scan_state = ScanState(scan_id, target, total_modules)
            self._scans[scan_id] = scan_state
            logger.info(f"Created scan state: {scan_id} for target: {target}")
            return scan_id
    
    async def get_scan(self, scan_id: str) -> ScanState | None:
        """
        Get scan state by ID.
        
        Args:
            scan_id: The scan ID
            
        Returns:
            ScanState if found, None otherwise
        """
        async with self._lock:
            return self._scans.get(scan_id)
    
    async def update_status(self, scan_id: str, status: ScanStatus) -> None:
        """
        Update scan status.
        
        Args:
            scan_id: The scan ID
            status: New status
        """
        async with self._lock:
            scan_state = self._scans.get(scan_id)
            if scan_state:
                scan_state.status = status
                if status == ScanStatus.RUNNING and scan_state.start_time is None:
                    scan_state.start_time = datetime.now()
                elif status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                    scan_state.end_time = datetime.now()
                    if scan_state.start_time:
                        scan_state.duration_seconds = (
                            scan_state.end_time - scan_state.start_time
                        ).total_seconds()
                logger.info(f"Updated scan {scan_id} status to {status.value}")
    
    async def add_module_result(self, scan_id: str, result: ScanResult) -> None:
        """
        Add a module result to the scan state.
        
        Args:
            scan_id: The scan ID
            result: The scan result from a module
        """
        async with self._lock:
            scan_state = self._scans.get(scan_id)
            if scan_state:
                scan_state.results.append(result)
                scan_state.modules_completed.append(result.module_name)
                logger.info(f"Added result for module {result.module_name} to scan {scan_id}")
    
    async def set_error(self, scan_id: str, error: str) -> None:
        """
        Set error message for a failed scan.
        
        Args:
            scan_id: The scan ID
            error: Error message
        """
        async with self._lock:
            scan_state = self._scans.get(scan_id)
            if scan_state:
                scan_state.error = error
                scan_state.status = ScanStatus.FAILED
                scan_state.end_time = datetime.now()
                if scan_state.start_time:
                    scan_state.duration_seconds = (
                        scan_state.end_time - scan_state.start_time
                    ).total_seconds()
                logger.error(f"Scan {scan_id} failed: {error}")
    
    async def set_risk_analysis(self, scan_id: str, risk_analysis: RiskAnalysisResult) -> None:
        """
        Set risk analysis results for a completed scan.
        
        Args:
            scan_id: The scan ID
            risk_analysis: The risk analysis result
        """
        async with self._lock:
            scan_state = self._scans.get(scan_id)
            if scan_state:
                scan_state.risk_analysis = risk_analysis
                logger.info(f"Set risk analysis for scan {scan_id}")
    
    async def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan state entry.
        
        Args:
            scan_id: The scan ID
            
        Returns:
            True if deleted, False if not found
        """
        async with self._lock:
            if scan_id in self._scans:
                del self._scans[scan_id]
                logger.info(f"Deleted scan state: {scan_id}")
                return True
            return False
    
    async def get_all_scans(self) -> list[dict[str, Any]]:
        """
        Get all scan states.
        
        Returns:
            List of scan state dictionaries
        """
        async with self._lock:
            return [state.to_dict() for state in self._scans.values()]
