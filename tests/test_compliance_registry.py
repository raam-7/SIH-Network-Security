import pytest

from backend.app.compliance import (
    Framework,
    Requirement,
    VerificationStatus,
    get_framework_mappings,
    get_requirement,
    get_requirements,
)
from backend.app.schemas import FindingSeverity


def test_cis_ssh_requirement_is_registered_with_prototype_provenance():
    requirement = get_requirement("CISCO-SSH-001")

    assert requirement is not None
    assert requirement.framework is Framework.CIS
    assert requirement.security_concept == "SSH_VERSION"
    assert requirement.property == "protocol_version"
    assert requirement.operator == "EQUALS"
    assert requirement.expected_value == 2
    assert requirement.source_ref == "TO_BE_VERIFIED"
    assert requirement.verification_status is VerificationStatus.PROTOTYPE


def test_unknown_requirement_returns_none():
    assert get_requirement("UNKNOWN-001") is None


def test_requirement_filters_are_deterministic():
    assert len(get_requirements(framework=Framework.CIS)) == 3
    assert len(get_requirements(vendor="cisco", platform="ios-xe")) == 3
    assert get_requirements(framework=Framework.NIST) == []


def test_requirement_validation_rejects_empty_metadata():
    with pytest.raises(ValueError, match="non-empty"):
        Requirement(
            requirement_id=" ", framework=Framework.CIS, framework_version="1",
            vendor="cisco", platform="ios-xe", security_concept="SSH_VERSION",
            property="protocol_version", operator="EQUALS", expected_value=2,
            severity=FindingSeverity.MEDIUM, source_ref="S14",
            verification_status=VerificationStatus.PROTOTYPE,
            description="SSH version", remediation="ip ssh version 2",
        )


def test_framework_mappings_remain_distinct_and_provenance_aware():
    mappings = get_framework_mappings("CISCO-SSH-001")
    by_framework = {item.framework: item for item in mappings}

    assert by_framework[Framework.NIST].verification_status is VerificationStatus.TO_BE_VERIFIED
    assert by_framework[Framework.CISCO].source_ref == "S8"
    assert by_framework[Framework.CISCO].verification_status is VerificationStatus.PROTOTYPE
    assert by_framework[Framework.NIST] != by_framework[Framework.CISCO]


def test_existing_requirement_does_not_change_compliance_rule_behavior():
    from backend.app.compliance import ComplianceEngine
    from backend.app.schemas import Evidence, SecurityFact

    fact = SecurityFact(
        vendor="cisco", platform="ios-xe", raw_command="ip ssh version 2",
        security_domain="REMOTE_MANAGEMENT", security_concept="SSH_VERSION",
        property="protocol_version", value=2, confidence=1.0,
        mapping_source="deterministic_mapping",
        evidence=Evidence(line_start=1, line_end=1, exact_text="ip ssh version 2"),
    )
    assert ComplianceEngine().evaluate(fact).result.value == "PASS"


def test_aaa_requirement_is_source_backed_and_typed():
    requirement = get_requirement("CISCO-AAA-001")

    assert requirement is not None
    assert requirement.framework_version == "2.2.1"
    assert requirement.source_ref == "1.1.1"
    assert requirement.security_concept == "AAA"
    assert requirement.property == "authentication_mode"
    assert requirement.expected_value == "aaa"
    assert requirement.verification_status is VerificationStatus.VERIFIED


def test_vty_ssh_requirement_is_source_backed_and_typed():
    requirement = get_requirement("CISCO-VTY-SSH-001")

    assert requirement is not None
    assert requirement.framework is Framework.CIS
    assert requirement.framework_version == "2.2.1"
    assert requirement.source_ref == "1.2.2"
    assert requirement.security_concept == "VTY_TRANSPORT"
    assert requirement.property == "allowed_protocols"
    assert requirement.expected_value == ["ssh"]
    assert requirement.verification_status is VerificationStatus.VERIFIED
