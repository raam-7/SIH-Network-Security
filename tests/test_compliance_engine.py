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


@pytest.mark.parametrize("value", [1, 0, 3])
def test_unacceptable_ssh_versions_fail(value):
    finding = ComplianceEngine().evaluate(fact(value))
    assert finding.result is FindingResult.FAIL
    assert finding.remediation == "ip ssh version 2"
    assert finding.evidence.exact_text == "source command"


def test_missing_ssh_fact_is_manual_without_fabricated_command_evidence():
    finding = ComplianceEngine().evaluate_all([fact(2, concept="AAA", property_name="authentication_mode")])[0]
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


def test_wrong_concept_or_property_produces_no_ssh_finding():
    engine = ComplianceEngine()
    assert engine.evaluate(fact(2, concept="AAA", property_name="authentication_mode")) is None
    assert engine.evaluate(fact(2, property_name="enabled")) is None


def test_evidence_is_preserved_exactly_and_fact_is_not_mutated():
    original = fact(2, line=44)
    snapshot = original.model_copy(deep=True)
    finding = ComplianceEngine().evaluate(original)
    assert finding.evidence is original.evidence
    assert original == snapshot


def test_repeated_facts_are_evaluated_per_statement():
    findings = ComplianceEngine().evaluate_all([fact(1, line=20), fact(2, line=30)])
    assert [finding.result for finding in findings] == [FindingResult.FAIL, FindingResult.PASS]
    assert [finding.evidence.line_start for finding in findings] == [20, 30]


def test_fixture_pipeline_produces_findings_for_actual_ssh_facts():
    commands = parse_cisco_config(Path("examples/cisco/02_ssh_variants.cfg"))
    facts = [CiscoSecurityFactMapper().map(command) for command in commands]
    facts = [item for item in facts if item is not None and item.security_concept == "SSH_VERSION"]
    findings = ComplianceEngine().evaluate_all(facts)
    assert [(finding.result, finding.observed_value, finding.evidence.line_start) for finding in findings] == [
        (FindingResult.PASS, 2, 11),
        (FindingResult.FAIL, 1, 29),
        (FindingResult.PASS, 2, 31),
    ]
