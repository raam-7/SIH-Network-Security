"""Cisco IOS / IOS-XE structure-preserving configuration parser.

This module converts configuration text into canonical ``ParsedCommand`` objects.
It deliberately does not interpret security meaning or make compliance decisions.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple, Union

from backend.app.schemas.parsed_command import ParsedCommand


SECTION_HEADER_PREFIXES: Tuple[str, ...] = (
    "interface ", "line ", "router ", "ip access-list ", "ipv6 access-list ",
    "mac access-list ", "tacacs server ", "radius server ", "tacacs-server ",
    "radius-server ", "route-map ", "crypto map ", "crypto isakmp ",
    "crypto ipsec ", "crypto pki ", "policy-map ", "class-map ",
    "vrf definition ", "ip vrf ", "control-plane", "vlan ", "archive",
    "track ", "zone ", "zone-pair ", "redundancy", "telemetry",
    "flow exporter ", "flow monitor ", "flow record ", "sampler ",
)
SUB_CONTEXT_PREFIXES: Tuple[str, ...] = ("address-family ",)
BANNER_PATTERN = re.compile(r"^banner\s+([a-zA-Z0-9_\-]+)\s*(.*)$", re.IGNORECASE)


class CiscoParser:
    """Parse Cisco IOS/IOS-XE configuration while preserving physical evidence."""

    def parse(self, config_text: str) -> List[ParsedCommand]:
        if config_text.startswith("\ufeff"):
            config_text = config_text[1:]

        lines = config_text.splitlines()
        commands: List[ParsedCommand] = []
        context_stack: List[Tuple[str, int]] = []
        i = 0
        total_lines = len(lines)

        while i < total_lines:
            raw_line = lines[i]
            physical_line_num = i + 1
            expanded_line = raw_line.expandtabs(4)
            stripped_line = raw_line.strip()
            indent = len(expanded_line) - len(expanded_line.lstrip())

            if not stripped_line:
                i += 1
                continue

            if stripped_line.startswith("!"):
                if indent == 0:
                    context_stack.clear()
                i += 1
                continue

            if BANNER_PATTERN.match(stripped_line):
                banner_cmd, consumed_lines = self._parse_banner(
                    lines, i, physical_line_num, context_stack
                )
                commands.append(banner_cmd)
                i += consumed_lines
                continue

            lower_cmd = stripped_line.lower()
            if lower_cmd == "exit-address-family":
                cmd_parent = context_stack[-1][0] if context_stack else None
                if context_stack:
                    context_stack.pop()
                commands.append(ParsedCommand(
                    raw_command=stripped_line, line_start=physical_line_num,
                    line_end=physical_line_num, parent_context=cmd_parent,
                    parser_status="parsed",
                ))
                i += 1
                continue

            if lower_cmd == "exit":
                cmd_parent = context_stack[-1][0] if context_stack else None
                if context_stack:
                    context_stack.pop()
                commands.append(ParsedCommand(
                    raw_command=stripped_line, line_start=physical_line_num,
                    line_end=physical_line_num, parent_context=cmd_parent,
                    parser_status="parsed",
                ))
                i += 1
                continue

            if lower_cmd == "end":
                commands.append(ParsedCommand(
                    raw_command=stripped_line, line_start=physical_line_num,
                    line_end=physical_line_num, parent_context=None,
                    parser_status="parsed",
                ))
                context_stack.clear()
                i += 1
                continue

            if indent == 0:
                context_stack.clear()
            else:
                while context_stack and context_stack[-1][1] >= indent:
                    context_stack.pop()

            active_context = context_stack[-1][0] if context_stack else None
            is_section = self._is_section_initiator(stripped_line, indent, lines, i)
            commands.append(ParsedCommand(
                raw_command=stripped_line, line_start=physical_line_num,
                line_end=physical_line_num, parent_context=active_context,
                parser_status="parsed",
            ))
            if is_section:
                context_stack.append((stripped_line, indent))
            i += 1

        return commands

    def _is_section_initiator(
        self, command: str, current_indent: int, all_lines: List[str], current_idx: int
    ) -> bool:
        lower = command.lower()
        if current_indent == 0:
            for prefix in SECTION_HEADER_PREFIXES:
                if lower.startswith(prefix):
                    return True
        for prefix in SUB_CONTEXT_PREFIXES:
            if lower.startswith(prefix):
                return True
        for j in range(current_idx + 1, len(all_lines)):
            next_raw = all_lines[j]
            next_stripped = next_raw.strip()
            if not next_stripped or next_stripped.startswith("!"):
                continue
            next_expanded = next_raw.expandtabs(4)
            next_indent = len(next_expanded) - len(next_expanded.lstrip())
            return next_indent > current_indent
        return False

    def _parse_banner(
        self, lines: List[str], start_idx: int, start_line_num: int,
        context_stack: List[Tuple[str, int]],
    ) -> Tuple[ParsedCommand, int]:
        first_line = lines[start_idx]
        stripped_first = first_line.strip()
        match = BANNER_PATTERN.match(stripped_first)
        remainder = match.group(2).strip() if match else ""
        parent_context: Optional[str] = context_stack[-1][0] if context_stack else None

        if not remainder:
            return ParsedCommand(
                raw_command=stripped_first, line_start=start_line_num,
                line_end=start_line_num, parent_context=parent_context, parser_status="parsed",
            ), 1

        if remainder.startswith("^C") and (len(remainder) == 2 or remainder[2:].isspace()):
            delim, text_after = "^C", remainder[2:]
        else:
            delim, text_after = remainder[0], remainder[1:]

        if delim in text_after:
            return ParsedCommand(
                raw_command=stripped_first, line_start=start_line_num,
                line_end=start_line_num, parent_context=parent_context, parser_status="parsed",
            ), 1

        collected_lines = [first_line.rstrip("\r\n")]
        j = start_idx + 1
        total_lines = len(lines)
        while j < total_lines:
            current_line = lines[j]
            collected_lines.append(current_line.rstrip("\r\n"))
            if delim in current_line:
                end_line_num = j + 1
                full_raw = "\n".join(collected_lines)
                consumed_count = j - start_idx + 1
                return ParsedCommand(
                    raw_command=full_raw, line_start=start_line_num, line_end=end_line_num,
                    parent_context=parent_context, parser_status="parsed",
                ), consumed_count
            j += 1

        end_line_num = total_lines
        full_raw = "\n".join(collected_lines)
        consumed_count = total_lines - start_idx
        return ParsedCommand(
            raw_command=full_raw, line_start=start_line_num, line_end=end_line_num,
            parent_context=parent_context, parser_status="parsed",
        ), consumed_count


def parse_cisco_config(config: Union[str, Path]) -> List[ParsedCommand]:
    """Parse Cisco configuration text or a configuration file path."""
    if isinstance(config, Path):
        content = config.read_text(encoding="utf-8-sig", errors="replace")
    elif isinstance(config, str) and "\n" not in config and Path(config).is_file():
        content = Path(config).read_text(encoding="utf-8-sig", errors="replace")
    else:
        content = config
    return CiscoParser().parse(content)
