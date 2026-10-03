"""Vendor-neutral parser boundary with evidence-preserving implementations."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

from backend.app.schemas.parsed_command import ParsedCommand
from parsers.cisco import CiscoParser


class VendorParser(ABC):
    vendor: str
    platform: str

    @abstractmethod
    def parse(self, configuration: str) -> list[ParsedCommand]: ...


class CiscoVendorParser(VendorParser):
    vendor, platform = "cisco", "ios-xe"
    def parse(self, configuration: str) -> list[ParsedCommand]:
        return CiscoParser().parse(configuration)


class LineOrientedVendorParser(VendorParser):
    """Parse vendor syntax without interpreting security meaning."""
    def parse(self, configuration: str) -> list[ParsedCommand]:
        commands: list[ParsedCommand] = []
        for number, raw in enumerate(configuration.splitlines(), 1):
            text = raw.strip()
            if not text or text.startswith(("#", "!", "//")):
                continue
            commands.append(ParsedCommand(raw_command=text, line_start=number, line_end=number,
                                          parser_status="parsed"))
        return commands


def normalize_vendor(value: str) -> str:
    aliases = {"fortigate": "fortinet", "fortios": "fortinet", "panos": "palo_alto", "ios": "cisco"}
    normalized = value.strip().lower().replace("-", "_")
    return aliases.get(normalized, normalized)


def detect_vendor(configuration: str) -> str:
    """Conservative deterministic detection; ambiguity is an explicit error."""
    text = configuration.lower()
    fortinet = bool(re.search(r"(?m)^\s*config\s+system\b", text)) and all(
        re.search(rf"(?m)^\s*{token}\b", text) for token in ("set", "end")
    ) and bool(re.search(r"(?m)^\s*(edit|next)\b", text))
    juniper = "{" in text and "}" in text and ("system {" in text or "protocol-version" in text)
    palo_alto = "set deviceconfig" in text or "<config>" in text
    cisco_markers = re.findall(r"(?mi)^\s*(version\s+\d|hostname\s+|ip\s+ssh\s+|line\s+vty|aaa\s+new-model)", text)
    cisco = len(cisco_markers) >= 2 or bool(re.search(r"(?mi)^\s*(ip\s+ssh\s+|line\s+vty|aaa\s+new-model)", text))
    matches = [name for name, matched in (("fortinet", fortinet), ("juniper", juniper), ("palo_alto", palo_alto), ("cisco", cisco)) if matched]
    if len(matches) != 1:
        raise ValueError("unable to determine a unique supported vendor; select a vendor explicitly")
    return matches[0]


class JuniperParser(VendorParser):
    vendor, platform = "juniper", "junos"

    def parse(self, configuration: str) -> list[ParsedCommand]:
        """Parse set-style and brace-style Junos statements with hierarchy context."""
        commands: list[ParsedCommand] = []
        context: list[str] = []
        for number, raw in enumerate(configuration.splitlines(), 1):
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            # A closing brace ends the current Junos hierarchy before any
            # following statement on the same line is considered.
            while text.startswith("}"):
                if context:
                    context.pop()
                text = text[1:].strip()
            if not text:
                continue
            if text.startswith("set "):
                commands.append(ParsedCommand(raw_command=text, line_start=number, line_end=number,
                                              parent_context=" > ".join(context), parser_status="parsed"))
                continue
            if text.endswith("{"):
                header = text[:-1].strip()
                context.append(header)
                continue
            if text == "}":
                if context:
                    context.pop()
                continue
            if text.endswith(";"):
                commands.append(ParsedCommand(raw_command=text, line_start=number, line_end=number,
                                              parent_context=" > ".join(context), parser_status="parsed"))
        return commands


class FortinetParser(LineOrientedVendorParser):
    vendor, platform = "fortinet", "fortios"

    def parse(self, configuration: str) -> list[ParsedCommand]:
        commands: list[ParsedCommand] = []
        context: list[str] = []
        for number, raw in enumerate(configuration.splitlines(), 1):
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            if text in {"end", "next"}:
                if context:
                    context.pop()
                continue
            if text.startswith(("config ", "edit ")):
                context.append(text)
                continue
            if text.startswith("set "):
                commands.append(ParsedCommand(raw_command=text, line_start=number, line_end=number,
                    parent_context=" > ".join(context), parser_status="parsed"))
        return commands


class PaloAltoParser(LineOrientedVendorParser):
    vendor, platform = "palo_alto", "panos"


PARSERS: dict[str, type[VendorParser]] = {
    "cisco": CiscoVendorParser, "juniper": JuniperParser,
    "fortinet": FortinetParser, "fortigate": FortinetParser, "palo_alto": PaloAltoParser,
}


def get_vendor_parser(vendor: str) -> VendorParser:
    vendor = normalize_vendor(vendor)
    try:
        return PARSERS[vendor.lower()]()
    except KeyError as exc:
        raise ValueError(f"unsupported vendor: {vendor}") from exc

