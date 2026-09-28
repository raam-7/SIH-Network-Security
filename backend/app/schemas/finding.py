from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from .evidence import Evidence


class FindingResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Finding(BaseModel):
    """Compliance audit finding evaluated against a security rule."""

    rule_id: str = Field(..., description="Unique compliance rule identifier (e.g., 'CISCO-SSH-001')")
    result: FindingResult = Field(..., description="Evaluation result: PASS, FAIL, or MANUAL")
    severity: FindingSeverity = Field(..., description="Severity level: INFO, LOW, MEDIUM, HIGH, or CRITICAL")
    observed_value: Any = Field(default=None, description="Observed property value in the configuration")
    expected_value: Any = Field(default=None, description="Expected property value according to compliance rule")
    evidence: Evidence = Field(..., description="Exact configuration evidence supporting this finding")
    title: str = Field(..., description="Human-readable title describing the compliance check")
    description: str = Field(..., description="Detailed description of the check and finding")
    remediation: Optional[str] = Field(
        default=None,
        description="Remediation command or instructions to achieve compliance",
    )
