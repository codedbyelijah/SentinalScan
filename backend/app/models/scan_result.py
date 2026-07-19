from pydantic import BaseModel, Field

from app.models.enums import Status
from app.models.finding import Finding


class ScanResult(BaseModel):
    """Represents the result of a scan module execution."""
    
    module_name: str = Field(
        description="Name of the scan module that produced this result"
    )
    status: Status = Field(
        description="Execution status of the module"
    )
    execution_time: float = Field(
        description="Time taken to execute the module in seconds"
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="List of findings discovered by this module"
    )
