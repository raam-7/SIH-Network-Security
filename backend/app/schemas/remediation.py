"""Typed deterministic remediation plans."""

from enum import Enum

from pydantic import BaseModel, Field


class RemediationStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    NOT_REQUIRED = "NOT_REQUIRED"
    HUMAN_REVIEW = "HUMAN_REVIEW"


class RemediationPlan(BaseModel):
    status: RemediationStatus
    rule_id: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    title: str = Field(min_length=1)
    recommended_action: str = Field(min_length=1)
    configuration: str | None = None
    verification: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    safety_notes: list[str] = Field(default_factory=list)
    source: str = Field(min_length=1)
