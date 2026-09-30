"""Pure presentation aggregation for deterministic audit results."""

from collections import defaultdict, deque

from backend.app.schemas import FindingResult
from backend.app.schemas.audit_report import (
    AuditOverallStatus,
    AuditReport,
    AuditReportFinding,
    AuditSummary,
)

from .audit import AuditResult


class AuditReportService:
    """Build a report without re-running any pipeline stage."""

    def build_report(self, audit_result: AuditResult) -> AuditReport:
        assessments_by_rule = defaultdict(deque)
        for assessment in audit_result.risk_assessments:
            assessments_by_rule[assessment.rule_id].append(assessment)

        report_findings = []
        for finding in audit_result.findings:
            assessments = assessments_by_rule[finding.rule_id]
            if not assessments:
                raise ValueError(f"no risk assessment for finding {finding.rule_id}")
            assessment = assessments.popleft()
            report_findings.append(
                AuditReportFinding(
                    rule_id=finding.rule_id,
                    result=finding.result,
                    severity=finding.severity,
                    observed_value=finding.observed_value,
                    expected_value=finding.expected_value,
                    evidence=finding.evidence,
                    title=finding.title,
                    description=finding.description,
                    remediation=finding.remediation,
                    risk_level=assessment.risk_level,
                    is_actionable=assessment.is_actionable,
                    remediation_mode=assessment.remediation_mode,
                    rationale=assessment.rationale,
                )
            )

        if any(item.result is FindingResult.FAIL for item in audit_result.findings):
            status = AuditOverallStatus.NON_COMPLIANT
        elif any(item.result is FindingResult.MANUAL for item in audit_result.findings):
            status = AuditOverallStatus.REVIEW_REQUIRED
        else:
            status = AuditOverallStatus.COMPLIANT

        summary = AuditSummary(
            total_controls=len(audit_result.findings),
            passed=sum(item.result is FindingResult.PASS for item in audit_result.findings),
            failed=sum(item.result is FindingResult.FAIL for item in audit_result.findings),
            manual=sum(item.result is FindingResult.MANUAL for item in audit_result.findings),
            overall_status=status,
        )
        return AuditReport(
            vendor=audit_result.vendor,
            platform=audit_result.platform,
            summary=summary,
            findings=report_findings,
            parsed_command_count=audit_result.parsed_command_count,
            security_fact_count=audit_result.security_fact_count,
        )
