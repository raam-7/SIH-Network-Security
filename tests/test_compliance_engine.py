from pathlib import Path

import pytest

from backend.app.compliance import ComplianceEngine
from backend.app.normalization.cisco import CiscoSecurityFactMapper
from backend.app.schemas import Evidence, FindingResult, FindingSeverity, ParsedCommand, SecurityFact
from parsers.cisco import parse_cisco_config


def fact(value, *, concept="SSH_VERSION", property_name="protocol_version", line=10):
    return SecurityFact(
        vendor="cisco",
        platform="ios-xe",
        raw_command=f"ip ssh version {value}" if value is not None else "ip ssh version unknown",
        security_domain="REMOTE_MANAGEMENT",
        security_concept=concept,
        property=property_name,
        value=value,
        confidence=1.0,
        mapping_source="deterministic_mapping",
        evidence=Evidence(line_start=line, line_end=line, exact_text="source command"),
        parent_context=None,
    )


@pytest.mark.parametrize("value", [2])
def test_ssh_version_two_passes(value):
    finding = ComplianceEngine().evaluate(fact(value))
    assert finding.result is FindingResult.PASS
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.observed_value == 2
    assert finding.expected_value == 2
    assert finding.remediation is None
    assert finding.evidence.line_start == 10
    assert finding.evidence.exact_text == "source command"


@pytest.mark.parametrize("value", [1, 0, 3])
def test_unacceptable_ssh_versions_fail(value):
    finding = ComplianceEngine().evaluate(fact(value))
    assert finding.result is FindingResult.FAIL
    assert finding.remediation == "ip ssh version 2"
    assert finding.evidence.exact_text == "source command"


def test_missing_ssh_fact_is_manual_without_fabricated_command_evidence():
    finding = next(
        item
        for item in ComplianceEngine().evaluate_all([fact(2, concept="AAA", property_name="authentication_mode")])
        if item.rule_id == "CISCO-SSH-001"
    )
    assert finding.result is FindingResult.MANUAL
    assert finding.observed_value is None
    assert finding.expected_value == 2
    assert finding.evidence.exact_text == ""
    assert finding.evidence.line_start == finding.evidence.line_end == 1
    assert "not explicitly configured" in finding.title


def test_empty_facts_are_manual():
    finding = ComplianceEngine().evaluate_all([])[0]
    assert finding.result is FindingResult.MANUAL


def test_unresolved_ssh_value_is_manual():
    finding = ComplianceEngine().evaluate(fact(None))
    assert finding.result is FindingResult.MANUAL
    assert finding.observed_value is None
    assert finding.evidence.line_start == 10
    assert finding.evidence.exact_text == "source command"


def test_wrong_concept_or_property_produces_no_ssh_finding():
    engine = ComplianceEngine()
    assert engine.evaluate(fact(2, concept="NTP_AUTHENTICATION", property_name="enabled")) is None
    assert engine.evaluate(fact(2, property_name="enabled")) is None


def test_evidence_is_preserved_exactly_and_fact_is_not_mutated():
    original = fact(2, line=44)
    snapshot = original.model_copy(deep=True)
    finding = ComplianceEngine().evaluate(original)
    assert finding.evidence is original.evidence
    assert original == snapshot


def test_repeated_facts_are_evaluated_per_statement():
    findings = [
        finding
        for finding in ComplianceEngine().evaluate_all([fact(1, line=20), fact(2, line=30)])
        if finding.rule_id == "CISCO-SSH-001"
    ]
    assert [finding.result for finding in findings] == [FindingResult.FAIL, FindingResult.PASS]
    assert [finding.evidence.line_start for finding in findings] == [20, 30]


def test_fixture_pipeline_produces_findings_for_actual_ssh_facts():
    commands = parse_cisco_config(Path("examples/cisco/02_ssh_variants.cfg"))
    facts = [CiscoSecurityFactMapper().map(command) for command in commands]
    facts = [item for item in facts if item is not None and item.security_concept == "SSH_VERSION"]
    findings = [
        finding
        for finding in ComplianceEngine().evaluate_all(facts)
        if finding.rule_id == "CISCO-SSH-001"
    ]
    assert [(finding.result, finding.observed_value, finding.evidence.line_start) for finding in findings] == [
        (FindingResult.PASS, 2, 11),
        (FindingResult.FAIL, 1, 29),
        (FindingResult.PASS, 2, 31),
    ]
    assert [finding.evidence.exact_text for finding in findings] == [
        "ip ssh version 2",
        "ip ssh version 1",
        "ip ssh version 2",
    ]


def test_telnet_disabled_passes_with_evidence():
    command = ParsedCommand(
        raw_command="transport input ssh", line_start=2, line_end=2, parent_context="line vty 0 4"
    )
    security_fact = CiscoSecurityFactMapper().map(command)
    finding = ComplianceEngine().evaluate(security_fact)

    assert finding.rule_id == "CISCO-TELNET-001"
    assert finding.result is FindingResult.PASS
    assert finding.expected_value is False
    assert finding.evidence.line_start == 2
    assert finding.evidence.exact_text == "transport input ssh"
    assert finding.remediation is None


def test_aaa_new_model_passes_with_exact_evidence():
    command = ParsedCommand(raw_command="aaa new-model", line_start=14, line_end=14)
    security_fact = CiscoSecurityFactMapper().map(command)
    finding = ComplianceEngine().evaluate(security_fact)

    assert finding.rule_id == "CISCO-AAA-001"
    assert finding.result is FindingResult.PASS
    assert finding.severity is FindingSeverity.MEDIUM
    assert finding.evidence.line_start == 14
    assert finding.evidence.line_end == 14
    assert finding.evidence.exact_text == "aaa new-model"


@pytest.mark.parametrize(
    ("protocols", "result"),
    [(["ssh"], FindingResult.PASS), (["telnet"], FindingResult.FAIL), (["telnet", "ssh"], FindingResult.FAIL)],
)
def test_vty_ssh_only_rule_evaluates_allowed_protocols(protocols, result):
    security_fact = SecurityFact(
        vendor="cisco", platform="ios-xe", raw_command="transport input test",
        security_domain="REMOTE_MANAGEMENT", security_concept="VTY_TRANSPORT",
        property="allowed_protocols", value=protocols, confidence=1.0,
        mapping_source="deterministic_mapping",
        evidence=Evidence(line_start=4, line_end=4, exact_text="transport input test"),
        parent_context="line vty 0 4",
    )
    finding = ComplianceEngine().evaluate(security_fact)

    assert finding.rule_id == "CISCO-VTY-SSH-001"
    assert finding.result is result
    assert finding.evidence.line_start == 4
    assert finding.evidence.exact_text == "transport input test"
    if result is FindingResult.FAIL:
        assert finding.remediation == "Configure VTY transport input to permit SSH only."


def test_vty_ssh_only_unresolved_and_absent_are_manual():
    unresolved = SecurityFact(
        vendor="cisco", platform="ios-xe", raw_command="transport input unknown",
        security_domain="REMOTE_MANAGEMENT", security_concept="VTY_TRANSPORT",
        property="allowed_protocols", value=None, confidence=1.0,
        mapping_source="deterministic_mapping",
        evidence=Evidence(line_start=6, line_end=6, exact_text="transport input unknown"),
        parent_context="line vty 0 4",
    )
    finding = ComplianceEngine().evaluate(unresolved)
    absent = next(item for item in ComplianceEngine().evaluate_all([fact(2)]) if item.rule_id == "CISCO-VTY-SSH-001")

    assert finding.result is FindingResult.MANUAL
    assert finding.evidence.exact_text == "transport input unknown"
    assert absent.result is FindingResult.MANUAL
    assert absent.evidence.line_start == absent.evidence.line_end == 1
    assert absent.evidence.exact_text == ""


def test_vty_fixture_pipeline_produces_pass_and_fail_findings():
    commands = parse_cisco_config("line vty 0 4\n transport input ssh\nline vty 5 15\n transport input telnet ssh\n")
    mapper = CiscoSecurityFactMapper()
    facts = [fact for command in commands for fact in mapper.map_commands(command)]
    findings = ComplianceEngine().evaluate_all(facts)
    vty_findings = [item for item in findings if item.rule_id == "CISCO-VTY-SSH-001"]

    assert [(item.result, item.evidence.line_start, item.evidence.exact_text) for item in vty_findings] == [
        (FindingResult.PASS, 2, "transport input ssh"),
        (FindingResult.FAIL, 4, "transport input telnet ssh"),
    ]


def test_missing_aaa_fact_is_manual():
    findings = ComplianceEngine().evaluate_all([fact(2)])
    aaa_finding = next(item for item in findings if item.rule_id == "CISCO-AAA-001")

    assert aaa_finding.result is FindingResult.MANUAL
    assert aaa_finding.observed_value is None
    assert aaa_finding.expected_value == "aaa"
    assert aaa_finding.evidence.exact_text == ""


def test_unrelated_aaa_value_does_not_pass():
    unrelated = SecurityFact(
        vendor="cisco", platform="ios-xe", raw_command="aaa authorization",
        security_domain="AUTHENTICATION", security_concept="AAA",
        property="authentication_mode", value="other", confidence=1.0,
        mapping_source="test", evidence=Evidence(line_start=15, line_end=15, exact_text="aaa authorization"),
    )
    finding = ComplianceEngine().evaluate(unrelated)

    assert finding.result is FindingResult.FAIL
    assert finding.rule_id == "CISCO-AAA-001"
    assert finding.evidence.exact_text == "aaa authorization"


@pytest.mark.parametrize("raw", ["transport input telnet", "transport input telnet ssh"])
def test_telnet_enabled_fails_with_deterministic_remediation(raw):
    command = ParsedCommand(raw_command=raw, line_start=7, line_end=7, parent_context="line vty 0 4")
    security_fact = CiscoSecurityFactMapper().map(command)
    finding = ComplianceEngine().evaluate(security_fact)

    assert finding.rule_id == "CISCO-TELNET-001"
    assert finding.result is FindingResult.FAIL
    assert finding.observed_value is True
    assert finding.remediation == "Configure VTY transport input to permit SSH only."
    assert finding.evidence.exact_text == raw


def test_unresolved_telnet_access_is_manual_and_preserves_evidence():
    unresolved = fact(None, concept="TELNET_ACCESS", property_name="enabled", line=19)
    unresolved.raw_command = "transport input unknown"
    unresolved.evidence.exact_text = "transport input unknown"
    finding = ComplianceEngine().evaluate(unresolved)

    assert finding.result is FindingResult.MANUAL
    assert finding.expected_value is False
    assert finding.evidence.line_start == 19
    assert finding.evidence.exact_text == "transport input unknown"


def test_telnet_absence_is_manual_without_fabricated_evidence():
    findings = ComplianceEngine().evaluate_all([fact(2)])
    telnet_finding = next(item for item in findings if item.rule_id == "CISCO-TELNET-001")

    assert telnet_finding.result is FindingResult.MANUAL
    assert telnet_finding.observed_value is None
    assert telnet_finding.expected_value is False
    assert telnet_finding.evidence.line_start == telnet_finding.evidence.line_end == 1
    assert telnet_finding.evidence.exact_text == ""


def test_unrelated_facts_do_not_generate_telnet_finding():
    finding = ComplianceEngine().evaluate(fact(2))

    assert finding.rule_id == "CISCO-SSH-001"


def test_multiple_telnet_facts_are_evaluated_per_statement_in_order():
    commands = [
        ParsedCommand(raw_command="transport input ssh", line_start=2, line_end=2, parent_context="line vty 0 4"),
        ParsedCommand(raw_command="transport input telnet", line_start=5, line_end=5, parent_context="line vty 0 4"),
    ]
    facts = [CiscoSecurityFactMapper().map(command) for command in commands]
    findings = ComplianceEngine().evaluate_all(facts)

    telnet_findings = [item for item in findings if item.rule_id == "CISCO-TELNET-001"]
    assert [item.result for item in telnet_findings] == [FindingResult.PASS, FindingResult.FAIL]
    assert [item.evidence.line_start for item in telnet_findings] == [2, 5]


def test_fail_finding_retains_exact_command_evidence_and_remediation():
    command = ParsedCommand(raw_command="ip ssh version 1", line_start=7, line_end=7)
    security_fact = CiscoSecurityFactMapper().map(command)
    finding = ComplianceEngine().evaluate(security_fact)

    assert finding.result is FindingResult.FAIL
    assert finding.evidence.line_start == finding.evidence.line_end == 7
    assert finding.evidence.exact_text == "ip ssh version 1"
    assert finding.remediation == "ip ssh version 2"
