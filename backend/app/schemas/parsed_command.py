from typing import Optional
from pydantic import BaseModel, Field, model_validator


class ParsedCommand(BaseModel):
    """A single configuration command parsed from device configuration."""

    raw_command: str = Field(..., description="Raw command text as extracted from the configuration")
    line_start: int = Field(..., ge=1, description="1-based starting line number")
    line_end: int = Field(..., ge=1, description="1-based ending line number")
    parent_context: Optional[str] = Field(
        default=None,
        description="Parent configuration block context (e.g., 'line vty 0 4' or 'router bgp 65000')",
    )
    parser_status: str = Field(
        default="parsed",
        description="Parsing status indicator (e.g., 'parsed', 'unknown', 'unrecognized')",
    )

    @model_validator(mode="after")
    def validate_line_range(self) -> "ParsedCommand":
        if self.line_end < self.line_start:
            raise ValueError(
                f"line_end ({self.line_end}) must be greater than or equal to line_start ({self.line_start})"
            )
        return self
