"""Deterministic Cisco IOS/IOS-XE command-to-security-fact mappings."""

from __future__ import annotations

import re
from typing import Optional

from backend.app.schemas import Evidence, ParsedCommand, SecurityFact


MAPPING_SOURCE = "deterministic_mapping"
_SSH_VERSION = re.compile(r"^ip\s+ssh\s+version\s+([12])$", re.IGNORECASE)
_TRANSPORT_INPUT = re.compile(r"^transport\s+input\s+(.+)$", re.IGNORECASE)
_LOGGING_HOST = re.compile(r"^(no\s+)?logging\s+host\s+(\S+)$", re.IGNORECASE)


class CiscoSecurityFactMapper:
    """Map only known Cisco commands to canonical security facts."""

    def map_command(self, command: ParsedCommand) -> Optional[SecurityFact]:
        raw = command.raw_command
        normalized = raw.strip()
        lower = normalized.lower()
        value = None
        domain = concept = property_name = None

        ssh_match = _SSH_VERSION.fullmatch(normalized)
        if ssh_match:
            domain, concept, property_name, value = (
                "REMOTE_MANAGEMENT", "SSH_VERSION", "protocol_version", int(ssh_match.group(1))
            )
        elif lower == "aaa new-model":
            domain, concept, property_name, value = (
                "AUTHENTICATION", "AAA", "authentication_mode", "aaa"
            )
        elif lower in {"ntp authenticate", "no ntp authenticate"}:
            domain, concept, property_name, value = (
                "TIME_SYNC", "NTP_AUTHENTICATION", "enabled", not lower.startswith("no ")
            )
        else:
            logging_match = _LOGGING_HOST.fullmatch(normalized)
            if logging_match:
                domain, concept, property_name, value = (
                    "LOGGING", "REMOTE_SYSLOG", "enabled", logging_match.group(1) is None
                )
            else:
                transport_match = _TRANSPORT_INPUT.fullmatch(normalized)
                is_vty = (command.parent_context or "").lower().startswith("line vty")
                if transport_match and is_vty:
                    transports = transport_match.group(1).lower().split()
                    domain, concept, property_name, value = (
                        "REMOTE_MANAGEMENT", "TELNET_ACCESS", "enabled", "telnet" in transports
                    )

        if concept is None:
            return None

        return SecurityFact(
            vendor="cisco",
            platform="ios-xe",
            raw_command=raw,
            security_domain=domain,
            security_concept=concept,
            property=property_name,
            value=value,
            confidence=1.0,
            mapping_source=MAPPING_SOURCE,
            evidence=Evidence(
                line_start=command.line_start,
                line_end=command.line_end,
                exact_text=raw,
            ),
            parent_context=command.parent_context,
        )

    def map(self, command: ParsedCommand) -> Optional[SecurityFact]:
        """Alias for callers that prefer a concise mapper interface."""
        return self.map_command(command)


def map_cisco_command(command: ParsedCommand) -> Optional[SecurityFact]:
    """Map one parsed Cisco command without retaining mapper state."""
    return CiscoSecurityFactMapper().map_command(command)
