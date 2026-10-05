from backend.app.risk import RemediationMode
from backend.app.schemas.audit_report import AuditOverallStatus
from backend.app.services import AuditReportService, AuditService


def report(configuration):
    return AuditReportService().build_report(AuditService().audit_cisco_config(configuration))


COMPLIANT = "aaa new-model\nip ssh version 2\nip ssh time-out 60\nline vty 0 4\n transport input ssh\n"
NON_COMPLIANT = "aaa new-model\nip ssh version 1\nip ssh time-out 120\nline vty 0 4\n transport input telnet\n"
MANUAL = "hostname TEST-ROUTER\ninterface GigabitEthernet0/0\n description Management\n"


def test_compliant_report_has_five_passes():
    result = report(COMPLIANT)

    assert result.summary.total_controls == 5
    assert result.summary.passed == 5
    assert result.summary.failed == result.summary.manual == 0
    assert result.summary.overall_status is AuditOverallStatus.COMPLIANT


def test_non_compliant_report_has_failures():
    result = report(NON_COMPLIANT)

    assert result.summary.failed >= 1
    assert result.summary.overall_status is AuditOverallStatus.NON_COMPLIANT


def test_manual_report_requires_review():
    result = report(MANUAL)

    assert result.summary.manual == 5
    assert result.summary.failed == 0
    assert result.summary.overall_status is AuditOverallStatus.REVIEW_REQUIRED


def test_mixed_status_precedence_is_deterministic():
    audit = AuditService().audit_cisco_config("ip ssh version 2\n")
    result = AuditReportService().build_report(audit)
    assert result.summary.overall_status is AuditOverallStatus.REVIEW_REQUIRED


def test_report_preserves_finding_and_risk_fields():
    result = report("ip ssh time-out 120\n")
    item = next(item for item in result.findings if item.rule_id == "CISCO-SSH-TIMEOUT-001")

    assert item.result.value == "FAIL"
    assert item.observed_value == 120
    assert item.expected_value == 60
    assert item.evidence.line_start == 1
    assert item.evidence.line_end == 1
    assert item.evidence.exact_text == "ip ssh time-out 120"
    assert item.remediation == "ip ssh time-out 60"
    assert item.remediation_mode is RemediationMode.COMMAND
    assert item.is_actionable is True


def test_report_preserves_counts_and_duplicate_rule_order():
    audit = AuditService().audit_cisco_config("ip ssh version 1\nip ssh version 2\n")
    result = AuditReportService().build_report(audit)

    assert result.parsed_command_count == audit.parsed_command_count
    assert result.security_fact_count == audit.security_fact_count
    ssh_items = [item for item in result.findings if item.rule_id == "CISCO-SSH-001"]
    assert [item.observed_value for item in ssh_items] == [1, 2]
