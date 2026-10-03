"""Presentation contract for deterministic audit results."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from backend.app.risk import RemediationMode
from .evidence import Evidence
from .finding import FindingResult, FindingSeverity
from .human_review import HumanReview
from .attack_scenario import AttackScenario


class AuditOverallStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class AuditSummary(BaseModel):
    total_controls: int = Field(..., ge=0)
    passed: int = Field(..., ge=0)
    failed: int = Field(..., ge=0)
    manual: int = Field(..., ge=0)
    informational: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    review_pending_count: int = Field(default=0, ge=0)
    review_completed_count: int = Field(default=0, ge=0)
    overall_status: AuditOverallStatus


class AuditReportFinding(BaseModel):
    rule_id: str
    result: FindingResult
    severity: FindingSeverity
    observed_value: Any = None
    expected_value: Any = None
    evidence: Evidence
    title: str
    description: str
    remediation: str | None = None
    risk_level: str
    is_actionable: bool
    remediation_mode: RemediationMode
    rationale: str
    evidence_score: int = Field(default=0, ge=0, le=100)
    evidence_type: str = "No supporting configuration evidence found."
    semantic_concept: str | None = None
    semantic_property: str | None = None
    semantic_value: Any = None
    ai_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    mapping_source: str | None = None
    review: "HumanReview | None" = None


class AuditReport(BaseModel):
    vendor: str
    platform: str
    summary: AuditSummary
    findings: list[AuditReportFinding] = Field(default_factory=list)
    parsed_command_count: int = Field(..., ge=0)
    security_fact_count: int = Field(..., ge=0)
    configuration_hash: str | None = None
    attack_scenarios: list[AttackScenario] = Field(default_factory=list)
    posture: Any = None

    @field_validator("configuration_hash")
    @classmethod
    def validate_configuration_hash(cls, value: str | None) -> str | None:
        if value is not None and (len(value) != 64 or any(char not in "0123456789abcdef" for char in value)):
            raise ValueError("configuration_hash must be 64 lowercase hexadecimal characters")
        return value
