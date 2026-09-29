"""Validated metadata for prototype compliance requirements and mappings."""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from backend.app.schemas import FindingSeverity


class Framework(str, Enum):
    CIS = "CIS"
    NIST = "NIST"
    CISCO = "CISCO"


class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    PROTOTYPE = "PROTOTYPE"
    TO_BE_VERIFIED = "TO_BE_VERIFIED"


class Requirement(BaseModel):
    requirement_id: str
    framework: Framework
    framework_version: str
    vendor: str
    platform: str
    security_concept: str
    property: str
    operator: str
    expected_value: Any
    severity: FindingSeverity
    source_ref: str
    verification_status: VerificationStatus
    description: str
    remediation: str

    @field_validator(
        "requirement_id", "framework_version", "vendor", "platform", "security_concept",
        "property", "operator", "source_ref", "description", "remediation",
    )
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be non-empty")
        return value


class FrameworkMapping(BaseModel):
    """A contextual relationship, distinct from an executable requirement."""

    requirement_id: str
    framework: Framework
    framework_version: str
    source_ref: str
    verification_status: VerificationStatus
    description: str

    @field_validator("requirement_id", "framework_version", "source_ref", "description")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("must be non-empty")
        return value
