from pydantic import BaseModel, Field


class ReachabilityResult(BaseModel):
    """Represents the result of a reachability check."""
    
    reachable: bool = Field(
        description="Whether the target responded to the reachability check"
    )
    response_time_ms: float | None = Field(
        default=None,
        description="Response time in milliseconds if available"
    )
    method_used: str = Field(
        description="Method used for the check (http or ping)"
    )
