from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import AuditORM, FindingORM, RiskAssessmentORM
from backend.app.schemas import Evidence, FindingResult, FindingSeverity
from backend.app.schemas.audit_history import AuditHistorySummary
from backend.app.schemas.audit_report import AuditOverallStatus, AuditReport, AuditReportFinding, AuditSummary


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
        findings = [AuditReportFinding(
            rule_id=item.rule_id, result=FindingResult(item.result), severity=FindingSeverity(item.severity),
            observed_value=item.observed_value, expected_value=item.expected_value,
            evidence=Evidence(line_start=item.evidence_line_start, line_end=item.evidence_line_end, exact_text=item.evidence_exact_text),
            title=item.title, description=item.description, remediation=item.remediation,
            risk_level=item.risk_level, is_actionable=item.is_actionable,
            remediation_mode=item.remediation_mode, rationale=item.rationale,
        ) for item in audit.findings]
        return AuditReport(
            vendor=audit.vendor, platform=audit.platform,
            summary=AuditSummary(total_controls=audit.total_controls, passed=audit.passed,
                failed=audit.failed, manual=audit.manual, informational=audit.informational,
                overall_status=AuditOverallStatus(audit.overall_status)),
            findings=findings, parsed_command_count=audit.parsed_command_count,
            security_fact_count=audit.security_fact_count, configuration_hash=audit.configuration_hash,
        )
