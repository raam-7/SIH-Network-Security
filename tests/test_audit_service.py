import pytest

from backend.app.schemas import FindingResult
from backend.app.services import AuditService
from backend.app.risk import RemediationMode


def test_ssh_version_two_audits_to_pass_and_non_actionable_risk():
    result = AuditService().audit_cisco_config("hostname R1\nip ssh version 2\n")

    assert result.vendor == "cisco"
    assert result.platform == "ios-xe"
    assert result.findings[0].result is FindingResult.PASS
    assert result.risk_assessments[0].is_actionable is False
    assert result.risk_assessments[0].remediation_mode is RemediationMode.NONE


def test_ssh_timeout_audit_integrates_pass_and_fail():
    passing = AuditService().audit_cisco_config("ip ssh time-out 60\n")
    failing = AuditService().audit_cisco_config("ip ssh time-out 120\n")

    pass_finding = next(item for item in passing.findings if item.rule_id == "CISCO-SSH-TIMEOUT-001")
    fail_finding = next(item for item in failing.findings if item.rule_id == "CISCO-SSH-TIMEOUT-001")
    assert pass_finding.result is FindingResult.PASS
    assert fail_finding.result is FindingResult.FAIL
    assert fail_finding.evidence.exact_text == "ip ssh time-out 120"


def test_ssh_version_one_preserves_finding_and_risk_traceability():
    result = AuditService().audit_cisco_config("hostname R1\nip ssh version 1\n")
    finding = result.findings[0]
    assessment = result.risk_assessments[0]

    assert finding.result is FindingResult.FAIL
    assert finding.severity.value == "MEDIUM"
    assert finding.remediation == "ip ssh version 2"
    assert finding.evidence.line_start == 2
    assert finding.evidence.exact_text == "ip ssh version 1"
    assert assessment.result is finding.result
    assert assessment.remediation_mode is RemediationMode.COMMAND


def test_missing_ssh_version_is_manual_with_no_fabricated_evidence():
    result = AuditService().audit_cisco_config("hostname R1\n")

    assert result.findings[0].result is FindingResult.MANUAL
    assert result.findings[0].evidence.exact_text == ""
    assert result.risk_assessments[0].remediation_mode is RemediationMode.MANUAL


def test_empty_or_whitespace_configuration_is_rejected():
    with pytest.raises(ValueError, match="configuration"):
        AuditService().audit_cisco_config("  \n\t")


def test_unsupported_commands_do_not_create_security_facts_and_order_is_stable():
    result = AuditService().audit_cisco_config("hostname R1\nunsupported command\nip ssh version 2\n")

    assert result.parsed_command_count == 3
    assert result.security_fact_count == 1
    assert result.findings[0].evidence.line_start == 3
    assert len(result.findings) == len(result.risk_assessments)
