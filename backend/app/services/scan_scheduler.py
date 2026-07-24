import asyncio
import logging
from datetime import datetime
from enum import Enum

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.memory import MemoryJobStore

from app.orchestrator.scan_orchestrator import ScanOrchestrator
from app.models.scan_request import ScanRequest


logger = logging.getLogger(__name__)


class ScheduleInterval(str, Enum):
    """Supported schedule intervals for recurring scans."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    CUSTOM = "custom"


class ScanSchedulerError(Exception):
    """Custom exception for scan scheduler errors."""
    pass


class ScanScheduler:
    """
    Schedules and manages automated scan execution.
    
    Uses APScheduler with in-memory job storage to schedule one-time
    and recurring scans through the Scan Orchestrator.
    """
    
    def __init__(self, orchestrator: ScanOrchestrator):
        """
        Initialize the scan scheduler.
        
        Args:
            orchestrator: ScanOrchestrator instance for executing scans
        """
        self.orchestrator = orchestrator
        
        # Configure scheduler with in-memory job store
        jobstores = {
            'default': MemoryJobStore()
        }
        
        self.scheduler = BackgroundScheduler(jobstores=jobstores)
        self._started = False
        
        logger.info("ScanScheduler initialized")
    
    def start(self) -> None:
        """
        Start the scheduler.
        
        Raises:
            ScanSchedulerError: If scheduler is already started
        """
        if self._started:
            raise ScanSchedulerError("Scheduler is already started")
        
        self.scheduler.start()
        self._started = True
        logger.info("ScanScheduler started")
    
    def shutdown(self) -> None:
        """
        Shutdown the scheduler and cancel all jobs.
        """
        if not self._started:
            logger.warning("Scheduler is not running, nothing to shutdown")
            return
        
        self.scheduler.shutdown(wait=False)
        self._started = False
        logger.info("ScanScheduler shutdown")
    
    def schedule_one_time(
        self,
        scan_request: ScanRequest,
        run_at: datetime,
        job_id: str | None = None
    ) -> str:
        """
        Schedule a one-time scan to run at a specific datetime.
        
        Args:
            scan_request: ScanRequest containing target and configuration
            run_at: Datetime when the scan should execute
            job_id: Optional custom job ID. Auto-generated if not provided.
            
        Returns:
            The job ID for the scheduled scan
            
        Raises:
            ScanSchedulerError: If job with same ID already exists
        """
        if not self._started:
            raise ScanSchedulerError("Scheduler must be started before scheduling jobs")
        
        # Generate job ID if not provided
        if job_id is None:
            target_id = scan_request.target.normalized_target.replace("://", "-").replace("/", "-").replace(":", "-")
            job_id = f"{target_id}-onetime-{run_at.strftime('%Y%m%d-%H%M%S')}"
        
        # Check for duplicate job ID
        if self.scheduler.get_job(job_id):
            raise ScanSchedulerError(f"Job with ID '{job_id}' already exists")
        
        # Schedule the job
        self.scheduler.add_job(
            func=self._execute_scan,
            trigger=DateTrigger(run_date=run_at),
            args=[scan_request],
            id=job_id,
            name=f"One-time scan for {scan_request.target.normalized_target}"
        )
        
        logger.info(f"Scheduled one-time scan with job ID: {job_id} at {run_at}")
        return job_id
    
    def schedule_recurring(
        self,
        scan_request: ScanRequest,
        interval: ScheduleInterval,
        interval_value: int | None = None,
        job_id: str | None = None
    ) -> str:
        """
        Schedule a recurring scan with specified interval.
        
        Args:
            scan_request: ScanRequest containing target and configuration
            interval: ScheduleInterval (HOURLY, DAILY, WEEKLY, or CUSTOM)
            interval_value: For CUSTOM interval, the value in minutes.
                           Ignored for HOURLY, DAILY, WEEKLY.
            job_id: Optional custom job ID. Auto-generated if not provided.
            
        Returns:
            The job ID for the scheduled scan
            
        Raises:
            ScanSchedulerError: If job with same ID already exists or invalid interval
        """
        if not self._started:
            raise ScanSchedulerError("Scheduler must be started before scheduling jobs")
        
        # Validate custom interval
        if interval == ScheduleInterval.CUSTOM:
            if interval_value is None or interval_value <= 0:
                raise ScanSchedulerError("CUSTOM interval requires a positive interval_value in minutes")
        
        # Generate job ID if not provided
        if job_id is None:
            target_id = scan_request.target.normalized_target.replace("://", "-").replace("/", "-").replace(":", "-")
            if interval == ScheduleInterval.CUSTOM:
                job_id = f"{target_id}-custom-{interval_value}min"
            else:
                job_id = f"{target_id}-{interval.value}"
        
        # Check for duplicate job ID
        if self.scheduler.get_job(job_id):
            raise ScanSchedulerError(f"Job with ID '{job_id}' already exists")
        
        # Determine trigger based on interval type
        if interval == ScheduleInterval.HOURLY:
            trigger = IntervalTrigger(hours=1)
        elif interval == ScheduleInterval.DAILY:
            trigger = IntervalTrigger(days=1)
        elif interval == ScheduleInterval.WEEKLY:
            trigger = IntervalTrigger(weeks=1)
        elif interval == ScheduleInterval.CUSTOM:
            trigger = IntervalTrigger(minutes=interval_value)
        else:
            raise ScanSchedulerError(f"Unsupported interval: {interval}")
        
        # Schedule the job
        self.scheduler.add_job(
            func=self._execute_scan,
            trigger=trigger,
            args=[scan_request],
            id=job_id,
            name=f"{interval.value} scan for {scan_request.target.normalized_target}"
        )
        
        logger.info(f"Scheduled recurring scan with job ID: {job_id} ({interval.value})")
        return job_id
    
    def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a scheduled job by its ID.
        
        Args:
            job_id: The job ID to cancel
            
        Returns:
            True if job was cancelled, False if job was not found
        """
        if not self._started:
            logger.warning("Cannot cancel jobs: scheduler is not running")
            return False
        
        job = self.scheduler.get_job(job_id)
        if job:
            self.scheduler.remove_job(job_id)
            logger.info(f"Cancelled job with ID: {job_id}")
            return True
        else:
            logger.warning(f"Job not found: {job_id}")
            return False
    
    def get_status(self) -> dict:
        """
        Get scheduler status information.
        
        Returns:
            Dictionary containing:
            - running: bool - whether scheduler is running
            - job_count: int - number of scheduled jobs
            - jobs: list - list of job details (id, name, next_run_time)
        """
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                'id': job.id,
                'name': job.name,
                'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None
            })
        
        return {
            'running': self._started,
            'job_count': len(jobs),
            'jobs': jobs
        }
    
    def _execute_scan(self, scan_request: ScanRequest) -> None:
        """
        Execute a scan request synchronously (called by scheduler).
        
        Wraps the async ScanOrchestrator.execute_scan() in asyncio.run()
        to work with APScheduler's synchronous job execution model.
        
        Args:
            scan_request: ScanRequest containing target and configuration
        """
        target = scan_request.target.normalized_target
        logger.info(f"Executing scheduled scan for: {target}")
        
        try:
            # Run the async scan in a new event loop
            results = asyncio.run(self.orchestrator.execute_scan(scan_request))
            logger.info(f"Scheduled scan completed for: {target}. Results: {len(results)} modules executed")
        except Exception as e:
            logger.error(f"Scheduled scan failed for {target}: {str(e)}")
            # Don't re-raise - let scheduler continue running other jobs
