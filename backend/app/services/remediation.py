"""Deterministic, vendor-scoped remediation plans for compliance findings."""

from backend.app.compliance.registry import get_requirement
from backend.app.schemas.finding import Finding, FindingResult
from backend.app.schemas.remediation import RemediationPlan, RemediationStatus


_CATALOG = {
    "CISCO-SSH-001": {
        "title": "Configure SSH version 2",
        "recommended_action": "Configure SSH version 2.",
        "configuration": "ip ssh version 2",
        "verification": "show ip ssh",
        "rationale": "SSH protocol version 2 is the deterministic requirement for this control.",
    },
    "CISCO-TELNET-001": {
        "title": "Disable Telnet access",
        "recommended_action": "Disable Telnet access.",
        "configuration": "transport input ssh",
        "verification": "show running-config | section line vty",
        "rationale": "VTY transport must not permit Telnet access.",
    },
    "CISCO-AAA-001": {
        "title": "Enable AAA new-model",
        "recommended_action": "Enable AAA new-model.",
        "configuration": "aaa new-model",
        "verification": "show running-config | include aaa new-model",
        "rationale": "The deterministic rule requires the AAA authentication mode to be aaa.",
    },
    "CISCO-VTY-SSH-001": {
        "title": "Configure VTY lines to allow SSH only",
        "recommended_action": "Configure VTY lines to allow SSH only.",
        "configuration": "transport input ssh",
        "verification": "show running-config | section line vty",
        "rationale": "VTY transport must be restricted to SSH only.",
    },
    "CISCO-SSH-TIMEOUT-001": {
        "title": "Configure the SSH timeout to 60 seconds or less",
        "recommended_action": "Configure the SSH timeout to 60 seconds or less.",
        "configuration": "ip ssh time-out 60",
        "verification": "show running-config | include ip ssh time-out",
        "rationale": "The deterministic rule allows an SSH timeout less than or equal to 60 seconds.",
    },
}


def get_remediation(finding: Finding, vendor: str) -> RemediationPlan:
    """Return a plan without changing the supplied finding."""
    normalized_vendor = vendor.strip().lower()
    entry = _CATALOG.get(finding.rule_id) if normalized_vendor == "cisco" else None
    requirement = get_requirement(finding.rule_id) if entry else None
    source = f"compliance registry: {requirement.source_ref}" if requirement else "deterministic compliance finding"

    if entry is None:
        return RemediationPlan(
            status=RemediationStatus.HUMAN_REVIEW, rule_id=finding.rule_id,
            vendor=normalized_vendor, title="Remediation requires human review",
            recommended_action="Review the finding using vendor-specific documentation.",
            verification="Confirm the vendor-specific control and configuration manually.",
            rationale="No deterministic remediation is registered for this vendor and rule.",
            safety_notes=["Do not apply commands from another vendor."], source=source,
        )

    status = (RemediationStatus.NOT_REQUIRED if finding.result is FindingResult.PASS
              else RemediationStatus.AVAILABLE if finding.result is FindingResult.FAIL
              else RemediationStatus.HUMAN_REVIEW)
    return RemediationPlan(
        status=status, rule_id=finding.rule_id, vendor=normalized_vendor,
        title=entry["title"], recommended_action=entry["recommended_action"],
        configuration=entry["configuration"] if status is RemediationStatus.AVAILABLE else None,
        verification=entry["verification"], rationale=entry["rationale"],
        safety_notes=["Validate the target device and current configuration before applying changes.",
                      "This plan does not change the compliance finding or posture."], source=source,
    )


build_remediation_plan = get_remediation
