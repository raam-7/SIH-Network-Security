from __future__ import annotations

from uuid import UUID
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import AuditORM, FindingORM, RiskAssessmentORM, HumanReviewORM
from backend.app.schemas import Evidence, FindingResult, FindingSeverity, HumanReview, HumanReviewDecision, HumanReviewStatus
from backend.app.schemas.audit_history import AuditHistorySummary
from backend.app.schemas.audit_report import AuditOverallStatus, AuditReport, AuditReportFinding, AuditSummary
from backend.app.services.attack_scenarios import build_attack_scenarios


class AuditRepository:
    def __init__(self, session: Session):
        self.session = session

    def save_report(self, report: AuditReport) -> UUID:
        audit = AuditORM(
            vendor=report.vendor, platform=report.platform,
            overall_status=report.summary.overall_status.value,
            total_controls=report.summary.total_controls, passed=report.summary.passed,
            failed=report.summary.failed, manual=report.summary.manual,
            informational=report.summary.informational,
            parsed_command_count=report.parsed_command_count,
            security_fact_count=report.security_fact_count,
            configuration_hash=report.configuration_hash,
        )
        for sequence, item in enumerate(report.findings):
            finding = FindingORM(
                sequence=sequence, rule_id=item.rule_id, result=item.result.value,
                severity=item.severity.value, observed_value=item.observed_value,
                expected_value=item.expected_value, evidence_line_start=item.evidence.line_start,
                evidence_line_end=item.evidence.line_end, evidence_exact_text=item.evidence.exact_text,
                title=item.title, description=item.description, remediation=item.remediation,
                risk_level=item.risk_level, is_actionable=item.is_actionable,
                remediation_mode=item.remediation_mode.value, rationale=item.rationale,
                evidence_score=item.evidence_score, evidence_type=item.evidence_type,
                semantic_concept=item.semantic_concept, semantic_property=item.semantic_property,
                semantic_value=item.semantic_value, ai_confidence=item.ai_confidence,
                mapping_source=item.mapping_source,
            )
            finding.risk_assessment = RiskAssessmentORM(
                rule_id=item.rule_id, result=item.result.value, severity=item.severity.value,
                risk_level=item.risk_level, is_actionable=item.is_actionable,
                rationale=item.rationale, remediation=item.remediation,
                remediation_mode=item.remediation_mode.value,
            )
            audit.findings.append(finding)
        self.session.add(audit)
        self.session.commit()
        return audit.id

    def get_report(self, audit_id: UUID) -> AuditReport | None:
        audit = self.session.get(AuditORM, audit_id)
        return self._to_report(audit) if audit else None

    def save_review(self, audit_id: UUID, review: HumanReview) -> HumanReview:
        audit = self.session.get(AuditORM, audit_id)
        if audit is None:
            raise ValueError("audit not found")
        finding = next((item for item in audit.findings if item.rule_id == review.rule_id and item.result == "MANUAL"), None)
        if finding is None:
            raise ValueError("MANUAL finding not found for audit")
        persisted = self.session.query(HumanReviewORM).filter_by(finding_id=finding.id).one_or_none()
        if persisted is None:
            persisted = HumanReviewORM(audit_id=audit_id, finding_id=finding.id)
            self.session.add(persisted)
        persisted.rule_id = review.rule_id
        persisted.original_result = review.original_result.value
        persisted.decision = review.decision.value
        persisted.reviewer = review.reviewer
        persisted.reviewer_reason = review.reviewer_reason
        persisted.status = "REVIEWED"
        persisted.reviewed_at = datetime.now(timezone.utc)
        self.session.commit()
        return HumanReview(review_id=str(persisted.id), rule_id=persisted.rule_id,
            original_result=FindingResult(persisted.original_result), decision=HumanReviewDecision(persisted.decision),
            reviewer=persisted.reviewer, reviewer_reason=persisted.reviewer_reason,
            status=HumanReviewStatus.REVIEWED, reviewed_at=persisted.reviewed_at)

    def list_summaries(
        self,
        limit: int = 50,
        offset: int = 0,
        vendor: str | None = None,
        platform: str | None = None,
        overall_status: AuditOverallStatus | None = None,
    ) -> tuple[list[AuditHistorySummary], int]:
        filters = []
        if vendor is not None:
            filters.append(AuditORM.vendor == vendor)
        if platform is not None:
            filters.append(AuditORM.platform == platform)
        if overall_status is not None:
            filters.append(AuditORM.overall_status == overall_status.value)

        statement = select(
            AuditORM.id, AuditORM.vendor, AuditORM.platform, AuditORM.overall_status,
            AuditORM.total_controls, AuditORM.passed, AuditORM.failed, AuditORM.manual,
            AuditORM.informational, AuditORM.parsed_command_count,
            AuditORM.security_fact_count, AuditORM.created_at,
        ).where(*filters).order_by(AuditORM.created_at.desc()).limit(limit).offset(offset)
        items = [AuditHistorySummary(
            audit_id=row.id, vendor=row.vendor, platform=row.platform,
            overall_status=AuditOverallStatus(row.overall_status),
            total_controls=row.total_controls, passed=row.passed, failed=row.failed,
            manual=row.manual, informational=row.informational,
            parsed_command_count=row.parsed_command_count,
            security_fact_count=row.security_fact_count, created_at=row.created_at,
        ) for row in self.session.execute(statement)]
        total = self.session.scalar(select(func.count(AuditORM.id)).where(*filters)) or 0
        return items, total

    def list_reports(self, limit: int = 50, offset: int = 0) -> list[AuditReport]:
        """Return complete reports for existing repository callers."""
        audits = self.session.scalars(
            select(AuditORM).order_by(AuditORM.created_at.desc()).limit(limit).offset(offset)
        ).all()
        return [self._to_report(audit) for audit in audits]

    @staticmethod
    def _to_report(audit: AuditORM) -> AuditReport:
        reviews_by_finding = {review.finding_id: review for review in audit.reviews}
        findings = [AuditReportFinding(
            rule_id=item.rule_id, result=FindingResult(item.result), severity=FindingSeverity(item.severity),
            observed_value=item.observed_value, expected_value=item.expected_value,
            evidence=Evidence(line_start=item.evidence_line_start, line_end=item.evidence_line_end, exact_text=item.evidence_exact_text),
            title=item.title, description=item.description, remediation=item.remediation,
            risk_level=item.risk_level, is_actionable=item.is_actionable,
            remediation_mode=item.remediation_mode, rationale=item.rationale,
            evidence_score=item.evidence_score or 0, evidence_type=item.evidence_type or "No supporting configuration evidence found.",
            semantic_concept=item.semantic_concept, semantic_property=item.semantic_property,
            semantic_value=item.semantic_value, ai_confidence=item.ai_confidence, mapping_source=item.mapping_source,
            review=HumanReview(review_id=str(review.id), rule_id=review.rule_id,
                original_result=FindingResult(review.original_result), decision=HumanReviewDecision(review.decision),
                reviewer=review.reviewer, reviewer_reason=review.reviewer_reason,
                status=HumanReviewStatus(review.status), reviewed_at=review.reviewed_at) if (review := reviews_by_finding.get(item.id)) else None,
        ) for item in audit.findings]
        return AuditReport(
            vendor=audit.vendor, platform=audit.platform,
            summary=AuditSummary(total_controls=audit.total_controls, passed=audit.passed,
                failed=audit.failed, manual=audit.manual, informational=audit.informational,
                overall_status=AuditOverallStatus(audit.overall_status)),
            findings=findings, parsed_command_count=audit.parsed_command_count,
            security_fact_count=audit.security_fact_count, configuration_hash=audit.configuration_hash,
            attack_scenarios=build_attack_scenarios(findings),
        )
