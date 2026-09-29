"""Human adjudication contract for uncertain compliance findings."""

from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator

from .evidence import Evidence
from .finding import FindingResult


class HumanReviewDecision(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"


class HumanReviewStatus(str, Enum):
    PENDING = "PENDING"
    REVIEWED = "REVIEWED"


class HumanReview(BaseModel):
    """A separate human adjudication of a MANUAL machine finding."""

    review_id: str = Field(..., description="Review identifier")
    rule_id: str = Field(..., description="Rule identifier under review")
    original_result: FindingResult = Field(..., description="Original machine result")
    decision: HumanReviewDecision
    reviewer: str
    reviewer_reason: str
    evidence_reference: Evidence | None = None
    status: HumanReviewStatus = HumanReviewStatus.PENDING

    @field_validator("review_id", "rule_id", "reviewer", "reviewer_reason")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be non-empty")
        return value

    @model_validator(mode="after")
    def validate_original_result(self) -> "HumanReview":
        if self.original_result is not FindingResult.MANUAL:
            raise ValueError("human review is only valid for MANUAL findings")
        return self
