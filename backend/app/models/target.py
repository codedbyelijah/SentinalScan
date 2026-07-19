from pydantic import BaseModel, Field

from app.models.enums import TargetType


class Target(BaseModel):
    """Represents a scan target with its normalized form."""
    
    original_input: str = Field(
        description="The original input provided by the user"
    )
    normalized_target: str = Field(
        description="The normalized form of the target for scanning"
    )
    target_type: TargetType = Field(
        description="The type of target (domain, url, ipv4, ipv6)"
    )
    protocol: str | None = Field(
        default=None,
        description="The protocol (http, https) if applicable"
    )
