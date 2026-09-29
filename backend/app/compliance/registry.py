"""Small static registry for prototype framework metadata."""

from typing import Optional

from .requirements import Framework, FrameworkMapping, Requirement, VerificationStatus
from backend.app.schemas import FindingSeverity


_REQUIREMENTS = (
    Requirement(
        requirement_id="CISCO-SSH-001",
        framework=Framework.CIS,
        framework_version="TO_BE_VERIFIED",
        vendor="cisco",
        platform="ios-xe",
        security_concept="SSH_VERSION",
        property="protocol_version",
        operator="EQUALS",
        expected_value=2,
        severity=FindingSeverity.MEDIUM,
        source_ref="TO_BE_VERIFIED",
        verification_status=VerificationStatus.PROTOTYPE,
        description="SSH protocol version must be 2.",
        remediation="ip ssh version 2",
    ),
    Requirement(
        requirement_id="CISCO-AAA-001",
        framework=Framework.CIS,
        framework_version="2.2.1",
        vendor="cisco",
        platform="ios-xe",
        security_concept="AAA",
        property="authentication_mode",
        operator="EQUALS",
        expected_value="aaa",
        severity=FindingSeverity.MEDIUM,
        source_ref="1.1.1",
        verification_status=VerificationStatus.VERIFIED,
        description="Enable aaa new-model for centralized authentication, authorization, and accounting.",
        remediation="aaa new-model",
    ),
)

_MAPPINGS = (
    FrameworkMapping(
        requirement_id="CISCO-SSH-001",
        framework=Framework.NIST,
        framework_version="CSF 2.0",
        source_ref="TO_BE_VERIFIED",
        verification_status=VerificationStatus.TO_BE_VERIFIED,
        description="Contextual mapping to NIST CSF 2.0 requires source review; it does not define the Cisco command requirement.",
    ),
    FrameworkMapping(
        requirement_id="CISCO-SSH-001",
        framework=Framework.CISCO,
        framework_version="IOS-XE 17.x",
        source_ref="S8",
        verification_status=VerificationStatus.PROTOTYPE,
        description="Cisco vendor documentation provides configuration semantics, not an independent compliance framework.",
    ),
)


def get_requirement(requirement_id: str) -> Optional[Requirement]:
    return next((item for item in _REQUIREMENTS if item.requirement_id == requirement_id), None)


def get_requirements(
    *, framework: Framework | None = None, vendor: str | None = None, platform: str | None = None
) -> list[Requirement]:
    return [
        item
        for item in _REQUIREMENTS
        if (framework is None or item.framework is framework)
        and (vendor is None or item.vendor == vendor)
        and (platform is None or item.platform == platform)
    ]


def get_framework_mappings(requirement_id: str | None = None) -> list[FrameworkMapping]:
    return [
        item for item in _MAPPINGS
        if requirement_id is None or item.requirement_id == requirement_id
    ]
