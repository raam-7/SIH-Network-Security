"""Risk and remediation interpretation for canonical compliance findings."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from backend.app.schemas import Finding, FindingResult, FindingSeverity


class RemediationMode(str, Enum):
    NONE = "NONE"
    MANUAL = "MANUAL"
    COMMAND = "COMMAND"


class RiskAssessment(BaseModel):
    """Deterministic risk interpretation derived from one Finding.

    ``severity`` is copied from the Finding. ``risk_level`` is ``NONE`` only
    for PASS findings; otherwise it references the Finding's severity value.
    """

    rule_id: str
    result: FindingResult
    severity: FindingSeverity
    risk_level: str
    is_actionable: bool
    rationale: str
    remediation: str | None = None
    remediation_mode: RemediationMode


class RiskEngine:
    """Interpret findings without re-evaluating compliance."""

    def assess(self, finding: Finding) -> RiskAssessment:
        if finding.result is FindingResult.PASS:
            return RiskAssessment(
                rule_id=finding.rule_id,
                result=finding.result,
                severity=finding.severity,
                risk_level="NONE",
                is_actionable=False,
                rationale=finding.description,
                remediation=None,
                remediation_mode=RemediationMode.NONE,
            )

        mode = (
            RemediationMode.COMMAND
            if finding.result is FindingResult.FAIL and self._is_command(finding.remediation)
            else RemediationMode.MANUAL
        )
        return RiskAssessment(
            rule_id=finding.rule_id,
            result=finding.result,
            severity=finding.severity,
            risk_level=finding.severity.value,
            is_actionable=True,
            rationale=finding.description,
            remediation=finding.remediation,
            remediation_mode=mode,
        )

    @staticmethod
    def _is_command(remediation: str | None) -> bool:
        """Recognize the concise configuration-command form used by findings."""
        if not remediation:
            return False
        text = remediation.strip()
        return "\n" not in text and not text.endswith(".") and not text.lower().startswith("verify ")
