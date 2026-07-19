from pydantic import BaseModel, Field

from app.models.enums import ScanMode
from app.models.target import Target


class ScanRequest(BaseModel):
    """Represents a request to initiate a scan."""
    
    target: Target = Field(
        description="The target to be scanned"
    )
    scan_mode: ScanMode = Field(
        description="The scan mode (full or custom)"
    )
    enabled_modules: list[str] = Field(
        default_factory=list,
        description="List of enabled scan modules for custom scans"
    )
