"""Small deterministic compliance engine for canonical security facts."""

from __future__ import annotations

from collections.abc import Iterable
from typing import List, Optional

from backend.app.schemas import Evidence, Finding, FindingResult, FindingSeverity, SecurityFact


class CiscoSSH001Rule:
    """Evaluate CISCO-SSH-001 for one applicable SSH fact.

    Facts are evaluated per statement. Effective running-config resolution,
    including any last-command-wins policy, is intentionally future work.
    """

    rule_id = "CISCO-SSH-001"
    expected_value = 2
    severity = FindingSeverity.MEDIUM

    def evaluate(self, fact: SecurityFact) -> Optional[Finding]:
        if fact.security_concept != "SSH_VERSION" or fact.property != "protocol_version":
            return None

        if fact.value is None:
            result = FindingResult.MANUAL
            title = "SSH protocol version requires manual verification"
            description = "An SSH version fact was found, but its protocol version is unresolved."
            remediation = "Verify or configure SSH protocol version 2."
        elif fact.value == self.expected_value:
            result = FindingResult.PASS
            title = "SSH protocol version is 2"
            description = "The configured SSH protocol version matches the required value of 2."
            remediation = None
        else:
            result = FindingResult.FAIL
            title = "SSH protocol version is not 2"
            description = "The configured SSH protocol version does not match the required value of 2."
            remediation = "ip ssh version 2"

        return Finding(
            rule_id=self.rule_id,
            result=result,
            severity=self.severity,
            observed_value=fact.value,
            expected_value=self.expected_value,
            evidence=fact.evidence,
            title=title,
            description=description,
            remediation=remediation,
        )


class CiscoTelnet001Rule:
    """Evaluate CISCO-TELNET-001 for one applicable Telnet fact."""

    rule_id = "CISCO-TELNET-001"
    expected_value = False
    severity = FindingSeverity.MEDIUM

    def evaluate(self, fact: SecurityFact) -> Optional[Finding]:
        if fact.security_concept != "TELNET_ACCESS" or fact.property != "enabled":
            return None

        if fact.value is None:
            result = FindingResult.MANUAL
            title = "Telnet access requires manual verification"
            description = "A Telnet access fact was found, but its enabled state is unresolved."
            remediation = "Verify that VTY lines permit SSH only and do not permit Telnet."
        elif fact.value is self.expected_value:
            result = FindingResult.PASS
            title = "Telnet access is disabled"
            description = "The VTY transport configuration does not permit Telnet access."
            remediation = None
        else:
            result = FindingResult.FAIL
            title = "Telnet access is enabled"
            description = "The VTY transport configuration permits Telnet access."
            remediation = "Configure VTY transport input to permit SSH only."

        return Finding(
            rule_id=self.rule_id,
            result=result,
            severity=self.severity,
            observed_value=fact.value,
            expected_value=self.expected_value,
            evidence=fact.evidence,
            title=title,
            description=description,
            remediation=remediation,
        )


class CiscoAAA001Rule:
    """Evaluate CISCO-AAA-001 for one applicable AAA fact."""

    rule_id = "CISCO-AAA-001"
    expected_value = "aaa"
    severity = FindingSeverity.MEDIUM

    def evaluate(self, fact: SecurityFact) -> Optional[Finding]:
        if fact.security_concept != "AAA" or fact.property != "authentication_mode":
            return None

        if fact.value is None:
            result = FindingResult.MANUAL
            title = "AAA configuration requires manual verification"
            description = "An AAA fact was found, but its authentication mode is unresolved."
            remediation = "Verify that aaa new-model is enabled."
        elif fact.value == self.expected_value:
            result = FindingResult.PASS
            title = "AAA new-model is enabled"
            description = "The configuration enables aaa new-model."
            remediation = None
        else:
            result = FindingResult.FAIL
            title = "AAA new-model is not enabled"
            description = 'The observed AAA authentication mode does not equal "aaa".'
            remediation = "aaa new-model"

        return Finding(
            rule_id=self.rule_id,
            result=result,
            severity=self.severity,
            observed_value=fact.value,
            expected_value=self.expected_value,
            evidence=fact.evidence,
            title=title,
            description=description,
            remediation=remediation,
        )


class CiscoVTYSSH001Rule:
    """Evaluate CISCO-VTY-SSH-001 for one VTY transport fact."""

    rule_id = "CISCO-VTY-SSH-001"
    expected_value = ["ssh"]
    severity = FindingSeverity.MEDIUM

    def evaluate(self, fact: SecurityFact) -> Optional[Finding]:
        if fact.security_concept != "VTY_TRANSPORT" or fact.property != "allowed_protocols":
            return None

        if fact.value is None:
            result = FindingResult.MANUAL
            title = "VTY SSH-only transport requires manual verification"
            description = "The allowed VTY transport protocols are unresolved."
            remediation = "Configure VTY transport input to permit SSH only."
        elif fact.value == self.expected_value:
            result = FindingResult.PASS
            title = "VTY transport permits SSH only"
            description = "The VTY transport configuration permits SSH and no other protocol."
            remediation = None
        else:
            result = FindingResult.FAIL
            title = "VTY transport permits protocols other than SSH"
            description = "The VTY transport configuration does not restrict access to SSH only."
            remediation = "Configure VTY transport input to permit SSH only."

        return Finding(
            rule_id=self.rule_id,
            result=result,
            severity=self.severity,
            observed_value=fact.value,
            expected_value=self.expected_value,
            evidence=fact.evidence,
            title=title,
            description=description,
            remediation=remediation,
        )


class CiscoSSHTimeout001Rule:
    """Evaluate CISCO-SSH-TIMEOUT-001 using a numeric upper bound."""

    rule_id = "CISCO-SSH-TIMEOUT-001"
    expected_value = 60
    severity = FindingSeverity.MEDIUM

    def evaluate(self, fact: SecurityFact) -> Optional[Finding]:
        if fact.security_concept != "SSH_TIMEOUT" or fact.property != "timeout_seconds":
            return None

        if fact.value is None or isinstance(fact.value, bool) or not isinstance(fact.value, int):
            result = FindingResult.MANUAL
            title = "SSH timeout requires manual verification"
            description = "The SSH timeout value is unresolved or not a valid numeric value."
            remediation = "Verify or configure SSH timeout to 60 seconds or less."
        elif fact.value <= self.expected_value:
            result = FindingResult.PASS
            title = "SSH timeout is within the allowed limit"
            description = "The configured SSH timeout is 60 seconds or less."
            remediation = None
        else:
            result = FindingResult.FAIL
            title = "SSH timeout exceeds the allowed limit"
            description = "The configured SSH timeout exceeds the maximum of 60 seconds."
            remediation = "ip ssh time-out 60"

        return Finding(
            rule_id=self.rule_id,
            result=result,
            severity=self.severity,
            observed_value=fact.value,
            expected_value=self.expected_value,
            evidence=fact.evidence,
            title=title,
            description=description,
            remediation=remediation,
        )


class ComplianceEngine:
    """Select and run deterministic compliance rules over SecurityFacts."""

    def __init__(self) -> None:
        self._ssh_rule = CiscoSSH001Rule()
        self._telnet_rule = CiscoTelnet001Rule()
        self._aaa_rule = CiscoAAA001Rule()
        self._vty_ssh_rule = CiscoVTYSSH001Rule()
        self._ssh_timeout_rule = CiscoSSHTimeout001Rule()

    def evaluate(self, fact: SecurityFact) -> Optional[Finding]:
        """Evaluate one fact; unrelated facts do not produce findings."""
        return (
            self._ssh_rule.evaluate(fact)
            or self._telnet_rule.evaluate(fact)
            or self._aaa_rule.evaluate(fact)
            or self._vty_ssh_rule.evaluate(fact)
            or self._ssh_timeout_rule.evaluate(fact)
        )

    def evaluate_all(self, facts: Iterable[SecurityFact]) -> List[Finding]:
        """Evaluate each applicable fact, or MANUAL when SSH evidence is absent."""
        fact_list = list(facts)
        findings = [finding for fact in fact_list if (finding := self.evaluate(fact)) is not None]
        if not any(
            fact.security_concept == "SSH_VERSION" and fact.property == "protocol_version"
            for fact in fact_list
        ):
            findings.append(self._manual_absence_finding())
        if not any(
            fact.security_concept == "TELNET_ACCESS" and fact.property == "enabled"
            for fact in fact_list
        ):
            findings.append(self._telnet_manual_absence_finding())
        if not any(
            fact.security_concept == "AAA" and fact.property == "authentication_mode"
            for fact in fact_list
        ):
            findings.append(self._aaa_manual_absence_finding())
        if not any(
            fact.security_concept == "VTY_TRANSPORT" and fact.property == "allowed_protocols"
            for fact in fact_list
        ):
            findings.append(self._vty_ssh_manual_absence_finding())
        if not any(
            fact.security_concept == "SSH_TIMEOUT" and fact.property == "timeout_seconds"
            for fact in fact_list
        ):
            findings.append(self._ssh_timeout_manual_absence_finding())
        return findings

    @staticmethod
    def _manual_absence_finding() -> Finding:
        # Evidence requires positive line numbers. For absence, the canonical
        # file-level sentinel is 1/1 with empty exact_text; this is not a
        # fabricated configuration line or command.
        return Finding(
            rule_id="CISCO-SSH-001",
            result=FindingResult.MANUAL,
            severity=FindingSeverity.MEDIUM,
            observed_value=None,
            expected_value=2,
            evidence=Evidence(line_start=1, line_end=1, exact_text=""),
            title="SSH protocol version was not explicitly configured",
            description="No explicit SSH_VERSION/protocol_version SecurityFact was found; verify the device configuration manually.",
            remediation="Verify or configure SSH protocol version 2.",
        )

    @staticmethod
    def _telnet_manual_absence_finding() -> Finding:
        return Finding(
            rule_id="CISCO-TELNET-001",
            result=FindingResult.MANUAL,
            severity=FindingSeverity.MEDIUM,
            observed_value=None,
            expected_value=False,
            evidence=Evidence(line_start=1, line_end=1, exact_text=""),
            title="Telnet access could not be determined",
            description="Telnet access could not be determined from the available configuration evidence.",
            remediation="Verify that VTY lines permit SSH only and do not permit Telnet.",
        )

    @staticmethod
    def _aaa_manual_absence_finding() -> Finding:
        return Finding(
            rule_id="CISCO-AAA-001",
            result=FindingResult.MANUAL,
            severity=FindingSeverity.MEDIUM,
            observed_value=None,
            expected_value="aaa",
            evidence=Evidence(line_start=1, line_end=1, exact_text=""),
            title="AAA configuration could not be determined",
            description="AAA configuration could not be determined from the available configuration evidence.",
            remediation="Verify that aaa new-model is enabled.",
        )

    @staticmethod
    def _vty_ssh_manual_absence_finding() -> Finding:
        return Finding(
            rule_id="CISCO-VTY-SSH-001",
            result=FindingResult.MANUAL,
            severity=FindingSeverity.MEDIUM,
            observed_value=None,
            expected_value=["ssh"],
            evidence=Evidence(line_start=1, line_end=1, exact_text=""),
            title="VTY SSH-only transport could not be determined",
            description="VTY transport configuration could not be determined from the available evidence.",
            remediation="Configure VTY transport input to permit SSH only.",
        )

    @staticmethod
    def _ssh_timeout_manual_absence_finding() -> Finding:
        return Finding(
            rule_id="CISCO-SSH-TIMEOUT-001",
            result=FindingResult.MANUAL,
            severity=FindingSeverity.MEDIUM,
            observed_value=None,
            expected_value=60,
            evidence=Evidence(line_start=1, line_end=1, exact_text=""),
            title="SSH timeout could not be determined",
            description="SSH timeout could not be determined from the available configuration evidence.",
            remediation="Verify or configure SSH timeout to 60 seconds or less.",
        )
