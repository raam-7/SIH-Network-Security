"""Application service for deterministic Cisco configuration audits."""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, Field

from backend.app.compliance import ComplianceEngine
from backend.app.normalization.cisco import CiscoSecurityFactMapper
from backend.app.normalization.multivendor import map_vendor_commands
from backend.app.services.posture import PostureScore, calculate_posture
from parsers.vendors import detect_vendor, get_vendor_parser, normalize_vendor
from backend.app.risk import RiskAssessment, RiskEngine
from backend.app.schemas import Finding
from parsers.cisco import parse_cisco_config


def hash_configuration(configuration: str) -> str:
    """Return the SHA-256 fingerprint of the exact configuration text."""
    return hashlib.sha256(configuration.encode("utf-8")).hexdigest()


class AuditResult(BaseModel):
    vendor: str = "cisco"
    platform: str = "ios-xe"
    findings: list[Finding] = Field(default_factory=list)
    risk_assessments: list[RiskAssessment] = Field(default_factory=list)
    parsed_command_count: int = Field(..., ge=0)
    security_fact_count: int = Field(..., ge=0)
    posture: PostureScore


class AuditService:
    """Orchestrate parsing, normalization, compliance, and risk assessment."""

    def __init__(self) -> None:
        self._mapper = CiscoSecurityFactMapper()
        self._compliance = ComplianceEngine()
        self._risk = RiskEngine()

    def audit_cisco_config(self, config_text: str) -> AuditResult:
        return self.audit_config("cisco", config_text)

    def audit_config(self, vendor: str, config_text: str) -> AuditResult:
        if not isinstance(config_text, str) or not config_text.strip():
            raise ValueError("configuration must contain non-whitespace text")

        vendor = detect_vendor(config_text) if vendor == "auto" else normalize_vendor(vendor)
        parser = get_vendor_parser(vendor)
        commands = parser.parse(config_text)
        facts = self._mapper.map_commands(commands) if vendor == "cisco" else map_vendor_commands(vendor, commands)
        findings = self._compliance.evaluate_all(facts, vendor=vendor)
        if vendor != "cisco":
            for finding in findings:
                finding.rule_id = finding.rule_id.replace("CISCO", vendor.upper())
                if finding.remediation and vendor != "cisco":
                    finding.remediation = None
        assessments = [self._risk.assess(finding) for finding in findings]
        return AuditResult(
            vendor=vendor, platform=parser.platform, findings=findings,
            risk_assessments=assessments,
            parsed_command_count=len(commands),
            security_fact_count=len(facts),
            posture=calculate_posture(findings),
        )
