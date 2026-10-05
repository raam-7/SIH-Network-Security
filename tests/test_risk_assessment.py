from pathlib import Path

from backend.app.compliance import ComplianceEngine
from backend.app.normalization.cisco import CiscoSecurityFactMapper
from backend.app.risk import RemediationMode, RiskEngine
from backend.app.schemas import Evidence, Finding, FindingResult, FindingSeverity
from parsers.cisco import parse_cisco_config


def finding(result, *, remediation=None, severity=FindingSeverity.MEDIUM):
    return Finding(
        rule_id="TEST-001",
        result=result,
        severity=severity,
        evidence=Evidence(line_start=4, line_end=4, exact_text="source"),
        title="Test finding",
        description="Test rationale",
        remediation=remediation,
    )


def test_pass_has_no_actionable_risk_or_remediation():
    assessment = RiskEngine().assess(finding(FindingResult.PASS))

    assert assessment.is_actionable is False
    assert assessment.risk_level == "NONE"
    assert assessment.remediation is None
    assert assessment.remediation_mode is RemediationMode.NONE


def test_fail_preserves_severity_and_classifies_command_remediation():
    assessment = RiskEngine().assess(
        finding(FindingResult.FAIL, remediation="ip ssh version 2", severity=FindingSeverity.HIGH)
    )

    assert assessment.is_actionable is True
    assert assessment.risk_level == "HIGH"
    assert assessment.severity is FindingSeverity.HIGH
    assert assessment.remediation == "ip ssh version 2"
    assert assessment.remediation_mode is RemediationMode.COMMAND


def test_manual_is_actionable_and_uses_manual_remediation_mode():
    assessment = RiskEngine().assess(
        finding(FindingResult.MANUAL, remediation="Verify or configure SSH protocol version 2.")
    )

    assert assessment.is_actionable is True
    assert assessment.risk_level == "MEDIUM"
    assert assessment.remediation_mode is RemediationMode.MANUAL


def test_risk_assessment_does_not_mutate_finding_or_evidence():
    original = finding(FindingResult.FAIL, remediation="ip ssh version 2")
    snapshot = original.model_copy(deep=True)

    RiskEngine().assess(original)

    assert original == snapshot
    assert original.evidence.exact_text == "source"


def test_result_and_evidence_are_copied_without_reinterpretation():
    original = finding(FindingResult.FAIL, remediation="ip ssh version 2")
    assessment = RiskEngine().assess(original)

    assert assessment.result is original.result
    assert assessment.rule_id == original.rule_id
    assert assessment.remediation == original.remediation


def test_cisco_missing_ssh_finding_is_manual_and_actionable():
    finding_from_engine = ComplianceEngine().evaluate_all([])[0]
    assessment = RiskEngine().assess(finding_from_engine)

    assert finding_from_engine.result is FindingResult.MANUAL
    assert assessment.is_actionable is True
    assert assessment.risk_level == "MEDIUM"
    assert assessment.remediation == "Verify or configure SSH protocol version 2."
    assert assessment.remediation_mode is RemediationMode.MANUAL
    assert finding_from_engine.evidence.exact_text == ""


def test_unknown_finding_is_handled_without_compliance_logic():
    assessment = RiskEngine().assess(
        Finding(
            rule_id="FUTURE-001",
            result=FindingResult.MANUAL,
            severity=FindingSeverity.INFO,
            evidence=Evidence(line_start=1, line_end=1, exact_text=""),
            title="Future check",
            description="Requires review",
            remediation=None,
        )
    )

    assert assessment.result is FindingResult.MANUAL
    assert assessment.risk_level == "INFO"
    assert assessment.remediation_mode is RemediationMode.MANUAL


def test_cisco_fixture_findings_integrate_with_risk_engine():
    commands = parse_cisco_config(Path("examples/cisco/02_ssh_variants.cfg"))
    facts = [CiscoSecurityFactMapper().map(command) for command in commands]
    facts = [fact for fact in facts if fact and fact.security_concept == "SSH_VERSION"]
    findings = [
        finding
        for finding in ComplianceEngine().evaluate_all(facts)
        if finding.rule_id == "CISCO-SSH-001"
    ]
    assessments = [RiskEngine().assess(finding) for finding in findings]

    assert [(item.result, item.risk_level, item.remediation_mode) for item in assessments] == [
        (FindingResult.PASS, "NONE", RemediationMode.NONE),
        (FindingResult.FAIL, "MEDIUM", RemediationMode.COMMAND),
        (FindingResult.PASS, "NONE", RemediationMode.NONE),
    ]
