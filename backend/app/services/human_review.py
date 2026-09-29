"""Service for creating non-persistent human review records."""

from uuid import uuid4

from backend.app.schemas import (
    Evidence,
    Finding,
    HumanReview,
    HumanReviewDecision,
)


class HumanReviewService:
    """Create a separate adjudication record without changing a Finding."""

    def create_review(
        self,
        finding: Finding,
        reviewer: str,
        decision: HumanReviewDecision,
        reviewer_reason: str,
        evidence_reference: Evidence | None = None,
    ) -> HumanReview:
        if finding.result.value != "MANUAL":
            raise ValueError("only MANUAL findings can be submitted for human review")

        return HumanReview(
            review_id=str(uuid4()),
            rule_id=finding.rule_id,
            original_result=finding.result,
            decision=decision,
            reviewer=reviewer,
            reviewer_reason=reviewer_reason,
            evidence_reference=evidence_reference or finding.evidence,
        )
