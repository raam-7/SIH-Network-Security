from copy import deepcopy

import pytest

from backend.app.compliance.engine import ComplianceEngine
from backend.app.schemas.security_fact import SecurityFact
from backend.app.schemas.finding import Finding, FindingResult, FindingSeverity
from backend.app.schemas.remediation import RemediationPlan, RemediationStatus
from backend.app.services.remediation import get_remediation
from backend.app.schemas.evidence import Evidence


RULES = ["CISCO-SSH-001", "CISCO-TELNET-001", "CISCO-AAA-001", "CISCO-VTY-SSH-001", "CISCO-SSH-TIMEOUT-001"]


def finding(rule_id="CISCO-SSH-001", result=FindingResult.FAIL, evidence_text="ip ssh version 1"):
    return Finding(rule_id=rule_id, result=result, severity=FindingSeverity.MEDIUM,
                   evidence=Evidence(line_start=1, line_end=1, exact_text=evidence_text),
                   title="test", description="test")


def test_schema_validation_and_catalog_coverage():
    with pytest.raises(ValueError):
        RemediationPlan(status="AVAILABLE", rule_id="", vendor="cisco", title="x", recommended_action="x", verification="x", rationale="x", source="x")
    for rule in RULES:
        assert get_remediation(finding(rule), "cisco").rule_id == rule


def test_statuses_and_safe_missing_evidence():
    assert get_remediation(finding(result=FindingResult.PASS), "cisco").status is RemediationStatus.NOT_REQUIRED
    assert get_remediation(finding(), "cisco").status is RemediationStatus.AVAILABLE
    manual = get_remediation(finding(result=FindingResult.MANUAL, evidence_text="unknown"), "cisco")
    assert manual.status is RemediationStatus.HUMAN_REVIEW and manual.configuration is None


def test_unknown_and_other_vendors_do_not_get_cisco_remediation():
    assert get_remediation(finding("UNKNOWN-001"), "cisco").status is RemediationStatus.HUMAN_REVIEW
    for vendor in ("juniper", "fortinet", "palo alto"):
        plan = get_remediation(finding(), vendor)
        assert plan.status is RemediationStatus.HUMAN_REVIEW
        assert plan.configuration is None


def test_finding_is_not_mutated():
    original = finding()
    before = deepcopy(original.model_dump())
    get_remediation(original, "cisco")
    assert original.model_dump() == before


def test_engine_finding_fields_remain_authoritative():
    evaluated = ComplianceEngine().evaluate
    item = evaluated(SecurityFact(
        vendor="cisco", platform="ios-xe", security_concept="SSH_VERSION", property="protocol_version",
        raw_command="ip ssh version 1", security_domain="REMOTE_MANAGEMENT", value=1,
        confidence=1.0, mapping_source="verified_vendor_mapping",
        evidence=Evidence(line_start=1, line_end=1, exact_text="ip ssh version 1")))
    snapshot = (item.result, item.severity, item.rule_id, item.evidence)
    get_remediation(item, "cisco")
    assert (item.result, item.severity, item.rule_id, item.evidence) == snapshot
