from typing import Any

from pydantic import BaseModel, Field

from .evidence import Evidence
from .finding import FindingResult, FindingSeverity


class ExplanationInput(BaseModel):
    rule_id: str
    result: FindingResult
    severity: FindingSeverity
    vendor: str
    platform: str
    semantic_concept: str | None = None
    semantic_property: str | None = None
    observed_value: Any = None
    expected_value: Any = None
    evidence: Evidence
    remediation: str | None = None


class FindingExplanation(BaseModel):
    explanation: str = Field(min_length=1)
    detected_condition: str = Field(min_length=1)
    expected_condition: str = Field(min_length=1)
    evidence_summary: str = Field(min_length=1)
    explanation_confidence: float = Field(ge=0.0, le=1.0)
    source: str = Field(min_length=1)
