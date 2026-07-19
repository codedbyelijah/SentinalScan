from pydantic import BaseModel, Field

from app.models.enums import Category, Severity


class Finding(BaseModel):
    """Represents a security finding discovered during scanning."""
    
    title: str = Field(
        description="Brief title of the finding"
    )
    description: str = Field(
        description="Detailed description of the finding"
    )
    severity: Severity = Field(
        description="Severity level of the finding"
    )
    category: Category = Field(
        description="Category of the finding"
    )
    affected_target: str = Field(
        description="The specific target component affected"
    )
    recommendation: str = Field(
        description="Recommended remediation steps"
    )
