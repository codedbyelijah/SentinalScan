from datetime import datetime
from pydantic import BaseModel, Field

from app.models.enums import Status
from app.models.scan_result import ScanResult
from app.models.target import Target


class Report(BaseModel):
    """Represents a consolidated security assessment report."""
    
    target: Target = Field(
        description="The target that was scanned"
    )
    generated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when the report was generated"
    )
    scan_duration: float = Field(
        description="Total duration of the scan in seconds"
    )
    overall_status: Status = Field(
        description="Overall status of the scan"
    )
    results: list[ScanResult] = Field(
        default_factory=list,
        description="List of results from all scan modules"
    )
