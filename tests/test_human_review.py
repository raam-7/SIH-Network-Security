import pytest

from backend.app.schemas import (
    Evidence,
    Finding,
    FindingResult,
    FindingSeverity,
    HumanReview,
    HumanReviewDecision,
    HumanReviewStatus,
)
from backend.app.services import HumanReviewService


def manual_finding(result=FindingResult.MANUAL):
    return Finding(
        rule_id="CISCO-SSH-001",
        result=result,
        severity=FindingSeverity.MEDIUM,
        evidence=Evidence(line_start=8, line_end=8, exact_text="uncertain command"),
        title="Manual review",
        description="Requires human verification",
        remediation="Verify manually.",
    )


def test_manual_finding_creates_pending_review_with_copied_fields():
    finding = manual_finding()
    review = HumanReviewService().create_review(
        finding, "alice", HumanReviewDecision.COMPLIANT, "Verified against approved policy."
    )

    assert review.review_id
    assert review.rule_id == finding.rule_id
    assert review.original_result is FindingResult.MANUAL
    assert review.decision is HumanReviewDecision.COMPLIANT
    assert review.status is HumanReviewStatus.PENDING


def test_non_compliant_decision_works():
    review = HumanReviewService().create_review(
        manual_finding(), "bob", HumanReviewDecision.NON_COMPLIANT, "Confirmed Telnet remains enabled."
    )

    assert review.decision is HumanReviewDecision.NON_COMPLIANT


@pytest.mark.parametrize("result", [FindingResult.PASS, FindingResult.FAIL])
def test_pass_or_fail_finding_cannot_create_review(result):
    with pytest.raises(ValueError, match="MANUAL"):
        HumanReviewService().create_review(
            manual_finding(result), "alice", HumanReviewDecision.COMPLIANT, "Reason"
        )


@pytest.mark.parametrize("reviewer", ["", "   ", "\t\n"])
def test_empty_reviewer_is_rejected(reviewer):
    with pytest.raises(ValueError, match="non-empty"):
        HumanReviewService().create_review(
            manual_finding(), reviewer, HumanReviewDecision.COMPLIANT, "Reason"
        )


@pytest.mark.parametrize("reason", ["", "   ", "\t\n"])
def test_empty_reviewer_reason_is_rejected(reason):
    with pytest.raises(ValueError, match="non-empty"):
        HumanReviewService().create_review(
            manual_finding(), "alice", HumanReviewDecision.COMPLIANT, reason
        )


def test_finding_evidence_is_preserved_when_no_review_evidence_is_supplied():
    finding = manual_finding()
    review = HumanReviewService().create_review(
        finding, "alice", HumanReviewDecision.COMPLIANT, "Reason"
    )

    assert review.evidence_reference == finding.evidence


def test_explicit_review_evidence_overrides_finding_evidence():
    explicit = Evidence(line_start=20, line_end=21, exact_text="reviewer evidence")
    review = HumanReviewService().create_review(
        manual_finding(), "alice", HumanReviewDecision.COMPLIANT, "Reason", explicit
    )

    assert review.evidence_reference == explicit


def test_original_finding_is_not_mutated():
    finding = manual_finding()
    snapshot = finding.model_copy(deep=True)

    HumanReviewService().create_review(
        finding, "alice", HumanReviewDecision.NON_COMPLIANT, "Reason"
    )

    assert finding == snapshot


def test_human_review_schema_rejects_non_manual_original_result():
    with pytest.raises(ValueError, match="MANUAL"):
        HumanReview(
            review_id="review-1",
            rule_id="RULE-1",
            original_result=FindingResult.PASS,
            decision=HumanReviewDecision.COMPLIANT,
            reviewer="alice",
            reviewer_reason="Reason",
        )


def test_human_review_decision_has_no_manual_value():
    assert "MANUAL" not in {decision.value for decision in HumanReviewDecision}
