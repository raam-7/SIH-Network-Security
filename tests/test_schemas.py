import pytest
from pydantic import ValidationError

from backend.app.schemas import (
    Evidence,
    Finding,
    FindingResult,
    FindingSeverity,
    ParsedCommand,
    SecurityFact,
)


# ==============================================================================
# Evidence Schema Tests
# ==============================================================================

def test_evidence_valid_single_line():
    evidence = Evidence(line_start=5, line_end=5, exact_text="ip ssh version 2")
    assert evidence.line_start == 5
    assert evidence.line_end == 5
    assert evidence.exact_text == "ip ssh version 2"


def test_evidence_valid_multi_line():
    multiline_text = "line vty 0 4\n transport input telnet"
    evidence = Evidence(line_start=10, line_end=11, exact_text=multiline_text)
    assert evidence.line_start == 10
    assert evidence.line_end == 11
    assert evidence.exact_text == multiline_text


def test_evidence_invalid_line_start_zero_or_negative():
    with pytest.raises(ValidationError):
        Evidence(line_start=0, line_end=5, exact_text="some text")

    with pytest.raises(ValidationError):
        Evidence(line_start=-1, line_end=5, exact_text="some text")


def test_evidence_invalid_line_end_less_than_line_start():
    with pytest.raises(ValidationError) as exc_info:
        Evidence(line_start=10, line_end=9, exact_text="invalid range")
    assert "line_end" in str(exc_info.value)


def test_evidence_missing_fields():
    with pytest.raises(ValidationError):
        Evidence(line_start=1)


# ==============================================================================
# ParsedCommand Schema Tests
# ==============================================================================

def test_parsed_command_example_specification():
    data = {
        "raw_command": "ip ssh version 2",
        "line_start": 5,
        "line_end": 5,
        "parent_context": None,
        "parser_status": "parsed",
    }
    cmd = ParsedCommand(**data)
    assert cmd.raw_command == "ip ssh version 2"
    assert cmd.line_start == 5
    assert cmd.line_end == 5
    assert cmd.parent_context is None
    assert cmd.parser_status == "parsed"


def test_parsed_command_with_parent_context():
    cmd = ParsedCommand(
        raw_command="transport input telnet",
        line_start=11,
        line_end=11,
        parent_context="line vty 0 4",
        parser_status="parsed",
    )
    assert cmd.parent_context == "line vty 0 4"
    assert cmd.parser_status == "parsed"


def test_parsed_command_defaults():
    cmd = ParsedCommand(
        raw_command="hostname SIH-R1",
        line_start=2,
        line_end=2,
    )
    assert cmd.parent_context is None
    assert cmd.parser_status == "parsed"


def test_parsed_command_unknown_status():
    cmd = ParsedCommand(
        raw_command="some unknown vendor proprietary command",
        line_start=50,
        line_end=50,
        parser_status="unknown",
    )
    assert cmd.parser_status == "unknown"


def test_parsed_command_invalid_line_range():
    with pytest.raises(ValidationError):
        ParsedCommand(
            raw_command="hostname SIH-R1",
            line_start=10,
            line_end=5,
        )


# ==============================================================================
# SecurityFact Schema Tests
# ==============================================================================

def test_security_fact_example_specification():
    fact_dict = {
        "vendor": "cisco",
        "platform": "ios-xe",
        "raw_command": "ip ssh version 2",
        "security_domain": "REMOTE_MANAGEMENT",
        "security_concept": "SSH_VERSION",
        "property": "protocol_version",
        "value": 2,
        "confidence": 1.0,
        "mapping_source": "verified_vendor_mapping",
        "evidence": {
            "line_start": 5,
            "line_end": 5,
            "exact_text": "ip ssh version 2",
        },
    }
    fact = SecurityFact(**fact_dict)
    assert fact.vendor == "cisco"
    assert fact.platform == "ios-xe"
    assert fact.security_domain == "REMOTE_MANAGEMENT"
    assert fact.security_concept == "SSH_VERSION"
    assert fact.property == "protocol_version"
    assert fact.value == 2
    assert fact.confidence == 1.0
    assert fact.mapping_source == "verified_vendor_mapping"
    assert isinstance(fact.evidence, Evidence)
    assert fact.evidence.line_start == 5
    assert fact.evidence.line_end == 5
    assert fact.evidence.exact_text == "ip ssh version 2"
    assert fact.parent_context is None


def test_security_fact_with_parent_context():
    evidence = Evidence(line_start=11, line_end=11, exact_text="transport input telnet")
    fact = SecurityFact(
        vendor="cisco",
        platform="ios-xe",
        raw_command="transport input telnet",
        security_domain="REMOTE_MANAGEMENT",
        security_concept="TELNET_ACCESS",
        property="telnet_enabled",
        value=True,
        confidence=1.0,
        mapping_source="verified_vendor_mapping",
        evidence=evidence,
        parent_context="line vty 0 4",
    )
    assert fact.parent_context == "line vty 0 4"
    assert fact.value is True


def test_security_fact_confidence_bounds():
    evidence = Evidence(line_start=1, line_end=1, exact_text="test")
    base_kwargs = dict(
        vendor="cisco",
        platform="ios-xe",
        raw_command="test",
        security_domain="TEST",
        security_concept="TEST_CONCEPT",
        property="test_prop",
        value="test_val",
        mapping_source="test_source",
        evidence=evidence,
    )

    # Valid boundaries
    fact_0 = SecurityFact(confidence=0.0, **base_kwargs)
    assert fact_0.confidence == 0.0

    fact_1 = SecurityFact(confidence=1.0, **base_kwargs)
    assert fact_1.confidence == 1.0

    # Invalid boundaries
    with pytest.raises(ValidationError):
        SecurityFact(confidence=-0.1, **base_kwargs)

    with pytest.raises(ValidationError):
        SecurityFact(confidence=1.01, **base_kwargs)


def test_security_fact_value_types():
    evidence = Evidence(line_start=1, line_end=1, exact_text="test")
    base_kwargs = dict(
        vendor="cisco",
        platform="ios-xe",
        raw_command="test",
        security_domain="TEST",
        security_concept="TEST_CONCEPT",
        property="test_prop",
        confidence=0.9,
        mapping_source="test",
        evidence=evidence,
    )

    # Integer
    assert SecurityFact(value=1, **base_kwargs).value == 1
    # String
    assert SecurityFact(value="disabled", **base_kwargs).value == "disabled"
    # Boolean
    assert SecurityFact(value=False, **base_kwargs).value is False
    # None
    assert SecurityFact(value=None, **base_kwargs).value is None
    # List
    assert SecurityFact(value=["192.168.1.1", "10.0.0.1"], **base_kwargs).value == ["192.168.1.1", "10.0.0.1"]


def test_security_fact_missing_required_fields():
    with pytest.raises(ValidationError):
        SecurityFact(
            vendor="cisco",
            # platform missing
            raw_command="ip ssh version 2",
        )


# ==============================================================================
# Finding Schema Tests
# ==============================================================================

def test_finding_pass():
    evidence = Evidence(line_start=5, line_end=5, exact_text="ip ssh version 2")
    finding = Finding(
        rule_id="CISCO-SSH-001",
        result=FindingResult.PASS,
        severity=FindingSeverity.MEDIUM,
        observed_value=2,
        expected_value=2,
        evidence=evidence,
        title="Cisco SSH Version Compliance",
        description="SSH must be configured to use protocol version 2.",
        remediation=None,
    )
    assert finding.result == FindingResult.PASS
    assert finding.result == "PASS"
    assert finding.severity == FindingSeverity.MEDIUM
    assert finding.severity == "MEDIUM"
    assert finding.observed_value == 2
    assert finding.expected_value == 2
    assert finding.remediation is None


def test_finding_fail_with_remediation():
    evidence = Evidence(line_start=5, line_end=5, exact_text="ip ssh version 1")
    finding = Finding(
        rule_id="CISCO-SSH-001",
        result=FindingResult.FAIL,
        severity=FindingSeverity.HIGH,
        observed_value=1,
        expected_value=2,
        evidence=evidence,
        title="Cisco SSH Version Compliance",
        description="SSH is configured with protocol version 1, which is insecure.",
        remediation="ip ssh version 2",
    )
    assert finding.result == "FAIL"
    assert finding.severity == "HIGH"
    assert finding.observed_value == 1
    assert finding.expected_value == 2
    assert finding.remediation == "ip ssh version 2"


def test_finding_manual_with_null_observed():
    evidence = Evidence(line_start=1, line_end=1, exact_text="! no ssh version specified")
    finding = Finding(
        rule_id="CISCO-SSH-001",
        result=FindingResult.MANUAL,
        severity=FindingSeverity.MEDIUM,
        observed_value=None,
        expected_value=2,
        evidence=evidence,
        title="Cisco SSH Version Compliance",
        description="SSH version could not be determined automatically.",
        remediation="Verify SSH configuration and set 'ip ssh version 2'",
    )
    assert finding.result == "MANUAL"
    assert finding.observed_value is None


def test_finding_all_severities():
    evidence = Evidence(line_start=1, line_end=1, exact_text="test")
    severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    for sev in severities:
        finding = Finding(
            rule_id="TEST-001",
            result=FindingResult.PASS,
            severity=sev,
            observed_value=True,
            expected_value=True,
            evidence=evidence,
            title="Severity test",
            description="Testing severities",
        )
        assert finding.severity == sev


def test_finding_invalid_result_raises():
    evidence = Evidence(line_start=1, line_end=1, exact_text="test")
    for invalid in ["UNKNOWN", "ERROR", "SKIP", "pass", "fail"]:
        with pytest.raises(ValidationError):
            Finding(
                rule_id="TEST-001",
                result=invalid,
                severity=FindingSeverity.LOW,
                observed_value=1,
                expected_value=1,
                evidence=evidence,
                title="Invalid test",
                description="Testing invalid result",
            )


def test_finding_invalid_severity_raises():
    evidence = Evidence(line_start=1, line_end=1, exact_text="test")
    for invalid in ["URGENT", "BLOCKER", "WARN", "medium"]:
        with pytest.raises(ValidationError):
            Finding(
                rule_id="TEST-001",
                result=FindingResult.PASS,
                severity=invalid,
                observed_value=1,
                expected_value=1,
                evidence=evidence,
                title="Invalid test",
                description="Testing invalid severity",
            )


def test_finding_dict_evidence_coercion():
    finding = Finding(
        rule_id="CISCO-SSH-001",
        result="PASS",
        severity="INFO",
        observed_value=2,
        expected_value=2,
        evidence={"line_start": 5, "line_end": 5, "exact_text": "ip ssh version 2"},
        title="Dict evidence",
        description="Pydantic should convert dict to Evidence instance",
    )
    assert isinstance(finding.evidence, Evidence)
    assert finding.evidence.exact_text == "ip ssh version 2"


# ==============================================================================
# Pipeline Contract Integration Test
# ==============================================================================

def test_full_pipeline_data_contracts_flow():
    # 1. Parsed command from config
    raw_cfg = "ip ssh version 2"
    parsed_cmd = ParsedCommand(
        raw_command=raw_cfg,
        line_start=5,
        line_end=5,
        parent_context=None,
        parser_status="parsed",
    )

    # 2. Evidence created from parsed command
    evidence = Evidence(
        line_start=parsed_cmd.line_start,
        line_end=parsed_cmd.line_end,
        exact_text=parsed_cmd.raw_command,
    )

    # 3. Security fact mapped from parsed command and evidence
    fact = SecurityFact(
        vendor="cisco",
        platform="ios-xe",
        raw_command=parsed_cmd.raw_command,
        security_domain="REMOTE_MANAGEMENT",
        security_concept="SSH_VERSION",
        property="protocol_version",
        value=2,
        confidence=1.0,
        mapping_source="verified_vendor_mapping",
        evidence=evidence,
        parent_context=parsed_cmd.parent_context,
    )

    # 4. Finding generated from fact evaluation
    finding = Finding(
        rule_id="CISCO-SSH-001",
        result=FindingResult.PASS if fact.value == 2 else FindingResult.FAIL,
        severity=FindingSeverity.MEDIUM,
        observed_value=fact.value,
        expected_value=2,
        evidence=fact.evidence,
        title="Cisco SSH Version 2 Requirement",
        description="Verifies that SSH protocol version 2 is explicitly enforced.",
        remediation="ip ssh version 2" if fact.value != 2 else None,
    )

    assert finding.result == FindingResult.PASS
    assert finding.observed_value == 2
    assert finding.evidence.exact_text == "ip ssh version 2"
    assert finding.evidence.line_start == 5
    assert finding.remediation is None

    # 5. Serialization sanity check
    dump = finding.model_dump()
    assert dump["rule_id"] == "CISCO-SSH-001"
    assert dump["result"] == "PASS"
    assert dump["severity"] == "MEDIUM"
    assert dump["evidence"]["exact_text"] == "ip ssh version 2"
