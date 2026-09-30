"""HTTP API for submitting human adjudications of uncertain findings."""

from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from uuid import UUID
from pydantic import BaseModel, field_validator

from backend.app.schemas import Evidence, Finding, HumanReview, HumanReviewDecision
from backend.app.services import HumanReviewService
from backend.app.db import get_session
from backend.app.services.audit_repository import AuditRepository


class HumanReviewRequest(BaseModel):
    audit_id: UUID | None = None
    finding: Finding
    decision: HumanReviewDecision
    reviewer: str
    reviewer_reason: str
    evidence_reference: Evidence | None = None

    @field_validator("reviewer", "reviewer_reason")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be non-empty")
        return value


router = APIRouter(prefix="/reviews", tags=["human-review"])


@router.post("", response_model=HumanReview)
def create_human_review(request: HumanReviewRequest, session: Session = Depends(get_session)):
    try:
        review = HumanReviewService().create_review(
            finding=request.finding,
            reviewer=request.reviewer,
            decision=request.decision,
            reviewer_reason=request.reviewer_reason,
            evidence_reference=request.evidence_reference,
        )
        if request.audit_id is not None:
            return AuditRepository(session).save_review(request.audit_id, review)
        return review
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
