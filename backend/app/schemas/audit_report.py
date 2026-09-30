"""Presentation contract for deterministic audit results."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.risk import RemediationMode
from .evidence import Evidence
from .finding import FindingResult, FindingSeverity


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


class AuditReport(BaseModel):
    vendor: str
    platform: str
    summary: AuditSummary
    findings: list[AuditReportFinding] = Field(default_factory=list)
    parsed_command_count: int = Field(..., ge=0)
    security_fact_count: int = Field(..., ge=0)
