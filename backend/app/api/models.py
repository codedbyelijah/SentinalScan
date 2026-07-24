from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import ScanMode, Severity


class ScanStatus(str, Enum):
    """Status of a scan execution."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportFormat(str, Enum):
    """Supported report export formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"


class ScheduleInterval(str, Enum):
    """Supported schedule intervals for recurring scans."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    CUSTOM = "custom"


# Request Models

class StartScanRequest(BaseModel):
    """Request to start a new scan."""
    target: str = Field(..., description="The target to scan (URL, domain, or IP)")
    scan_mode: ScanMode = Field(ScanMode.FULL, description="Scan mode (full or custom)")
    enabled_modules: list[str] = Field(default_factory=list, description="Enabled modules for custom scans")


class ScheduleScanRequest(BaseModel):
    """Request to schedule a scan."""
    target: str = Field(..., description="The target to scan (URL, domain, or IP)")
    scan_mode: ScanMode = Field(ScanMode.FULL, description="Scan mode (full or custom)")
    enabled_modules: list[str] = Field(default_factory=list, description="Enabled modules for custom scans")
    schedule_type: str = Field(..., description="Schedule type: 'one_time' or 'recurring'")
    run_at: datetime | None = Field(None, description="Datetime for one-time scan")
    interval: ScheduleInterval | None = Field(None, description="Interval for recurring scans")
    interval_value: int | None = Field(None, description="Interval value in minutes for CUSTOM interval")


# Response Models

class StartScanResponse(BaseModel):
    """Response from starting a scan."""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Initial scan status")
    message: str = Field(..., description="Response message")


class ScanStatusResponse(BaseModel):
    """Response with scan status information."""
    scan_id: str = Field(..., description="Scan identifier")
    status: ScanStatus = Field(..., description="Current scan status")
    target: str = Field(..., description="Target being scanned")
    start_time: datetime | None = Field(None, description="Scan start time")
    end_time: datetime | None = Field(None, description="Scan end time")
    duration_seconds: float | None = Field(None, description="Scan duration in seconds")
    modules_completed: list[str] = Field(default_factory=list, description="Completed module names")
    total_modules: int = Field(..., description="Total number of modules")
    error: str | None = Field(None, description="Error message if scan failed")


class FindingResponse(BaseModel):
    """Response model for a single finding."""
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Finding description")
    severity: Severity = Field(..., description="Finding severity")
    category: str = Field(..., description="Finding category")
    affected_target: str = Field(..., description="Affected target")
    recommendation: str = Field(..., description="Remediation recommendation")


class ScanResultsResponse(BaseModel):
    """Response with scan results."""
    scan_id: str = Field(..., description="Scan identifier")
    target: str = Field(..., description="Target that was scanned")
    overall_risk: str = Field(..., description="Overall risk level")
    total_findings: int = Field(..., description="Total number of findings")
    findings: list[FindingResponse] = Field(..., description="List of findings")
    scan_duration: float = Field(..., description="Scan duration in seconds")
    generated_at: datetime = Field(..., description="Results generation timestamp")


class ScheduleScanResponse(BaseModel):
    """Response from scheduling a scan."""
    job_id: str = Field(..., description="Scheduled job identifier")
    message: str = Field(..., description="Response message")


class ScheduleStatusResponse(BaseModel):
    """Response with scheduler status."""
    running: bool = Field(..., description="Whether scheduler is running")
    job_count: int = Field(..., description="Number of scheduled jobs")
    jobs: list[dict[str, Any]] = Field(..., description="List of scheduled job details")


class CancelScheduleResponse(BaseModel):
    """Response from cancelling a scheduled job."""
    cancelled: bool = Field(..., description="Whether job was cancelled")
    message: str = Field(..., description="Response message")
