"""Conservative mappings from verified vendor syntax to canonical SecurityFacts."""
from __future__ import annotations
import re
from collections.abc import Iterable
from backend.app.schemas import Evidence, ParsedCommand, SecurityFact

_PATTERNS = {
    "cisco": [(r"^ip ssh version ([12])$", "SSH_VERSION", "protocol_version", lambda m: int(m.group(1))),
              (r"^transport input (.+)$", "TELNET_ACCESS", "enabled", lambda m: "telnet" in m.group(1).lower().split())],
    "juniper": [(r"^(?:set system services ssh protocol-version v([12])|protocol-version v([12]);)$", "SSH_VERSION", "protocol_version", lambda m: int(next(group for group in m.groups() if group is not None))),
                (r"^(?:set system services telnet|telnet;)$", "TELNET_ACCESS", "enabled", lambda m: True)],
    "fortinet": [(r"^set allowaccess (.+)$", "TELNET_ACCESS", "enabled", lambda m: "telnet" in m.group(1).lower().split()),
                 (r"^set admin-telnet (enable|disable)$", "TELNET_ACCESS", "enabled", lambda m: m.group(1) == "enable")],
    "palo_alto": [(r"^set deviceconfig system service disable-telnet (yes|no)$", "TELNET_ACCESS", "enabled", lambda m: m.group(1) == "no")],
}

def map_vendor_commands(vendor: str, commands: Iterable[ParsedCommand]) -> list[SecurityFact]:
    vendor = "fortinet" if vendor == "fortigate" else vendor
    facts: list[SecurityFact] = []
    for command in commands:
        for pattern, concept, property_name, convert in _PATTERNS.get(vendor, []):
            match = re.fullmatch(pattern, command.raw_command, re.IGNORECASE)
            if match:
                facts.append(SecurityFact(vendor=vendor, platform={"cisco":"ios-xe","juniper":"junos","fortinet":"fortios","palo_alto":"panos"}[vendor], raw_command=command.raw_command,
                    security_domain="REMOTE_MANAGEMENT", security_concept=concept, property=property_name,
                    value=convert(match), confidence=1.0, mapping_source="verified_vendor_mapping",
                    evidence=Evidence(line_start=command.line_start, line_end=command.line_end, exact_text=command.raw_command), parent_context=command.parent_context))
                break
    return facts
