from pydantic import BaseModel, Field, model_validator


class Evidence(BaseModel):
    """Configuration evidence referencing exact source lines."""

    line_start: int = Field(..., ge=1, description="1-based starting line number in the source configuration")
    line_end: int = Field(..., ge=1, description="1-based ending line number in the source configuration")
    exact_text: str = Field(..., description="Exact configuration text matching the line range")

    @model_validator(mode="after")
    def validate_line_range(self) -> "Evidence":
        if self.line_end < self.line_start:
            raise ValueError(
                f"line_end ({self.line_end}) must be greater than or equal to line_start ({self.line_start})"
            )
        return self
