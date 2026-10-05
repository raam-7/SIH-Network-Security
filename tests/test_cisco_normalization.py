from pathlib import Path

import pytest

from backend.app.normalization.cisco import CiscoSecurityFactMapper, MAPPING_SOURCE
from backend.app.schemas import Evidence, ParsedCommand, SecurityFact
from parsers.cisco import parse_cisco_config


def parsed(raw, parent=None, start=10, end=None):
    return ParsedCommand(raw_command=raw, line_start=start, line_end=end or start, parent_context=parent)


@pytest.mark.parametrize(
    ("raw", "value"), [("ip ssh version 2", 2), ("ip ssh version 1", 1)]
)
def test_ssh_version_mapping(raw, value):
    fact = CiscoSecurityFactMapper().map_command(parsed(raw))
    assert isinstance(fact, SecurityFact)
    assert fact.security_concept == "SSH_VERSION"
    assert fact.value == value


@pytest.mark.parametrize(("raw", "value"), [("ip ssh time-out 60", 60), ("ip ssh time-out 30", 30)])
def test_ssh_timeout_mapping(raw, value):
    fact = CiscoSecurityFactMapper().map(parsed(raw, start=12))

    assert fact.security_concept == "SSH_TIMEOUT"
    assert fact.property == "timeout_seconds"
    assert fact.value == value
    assert fact.evidence.line_start == 12
    assert fact.evidence.exact_text == raw


def test_malformed_ssh_timeout_is_not_mapped():
    mapper = CiscoSecurityFactMapper()
    assert mapper.map(parsed("ip ssh time-out abc")) is None
    assert mapper.map(parsed("ip ssh time-out")) is None
    assert mapper.map(parsed("ip ssh time-out -1")) is None


def test_unknown_and_unrelated_commands_return_none():
    mapper = CiscoSecurityFactMapper()
    assert mapper.map_command(parsed("some future Cisco command")) is None
    assert mapper.map_command(parsed("logging buffered 64000")) is None
    assert mapper.map_command(parsed("transport input telnet", "interface GigabitEthernet0/1")) is None


@pytest.mark.parametrize(
    ("raw", "value"),
    [("transport input ssh", False), ("transport input telnet", True), ("transport input telnet ssh", True)],
)
def test_vty_transport_mapping(raw, value):
    fact = CiscoSecurityFactMapper().map(parsed(raw, "line vty 0 4", 22))
    assert fact.security_concept == "TELNET_ACCESS"
    assert fact.value is value
    assert fact.parent_context == "line vty 0 4"


@pytest.mark.parametrize(
    ("raw", "concept", "property_name", "value"),
    [
        ("aaa new-model", "AAA", "authentication_mode", "aaa"),
        ("ntp authenticate", "NTP_AUTHENTICATION", "enabled", True),
        ("no ntp authenticate", "NTP_AUTHENTICATION", "enabled", False),
        ("logging host 192.0.2.10", "REMOTE_SYSLOG", "enabled", True),
        ("no logging host 192.0.2.10", "REMOTE_SYSLOG", "enabled", False),
    ],
)
def test_other_deterministic_mappings(raw, concept, property_name, value):
    fact = CiscoSecurityFactMapper().map(parsed(raw, start=31))
    assert (fact.security_concept, fact.property, fact.value) == (concept, property_name, value)
    assert fact.raw_command == raw


def test_evidence_and_contract_are_preserved():
    command = parsed("ip ssh version 2", "router ospf 1", 40, 42)
    fact = CiscoSecurityFactMapper().map_command(command)
    assert isinstance(fact.evidence, Evidence)
    assert fact.evidence.line_start == 40
    assert fact.evidence.line_end == 42
    assert fact.evidence.exact_text == command.raw_command
    assert fact.vendor == "cisco"
    assert fact.platform == "ios-xe"
    assert 0.0 <= fact.confidence <= 1.0
    assert fact.mapping_source == MAPPING_SOURCE


def test_repeated_commands_are_not_deduplicated():
    commands = [parsed("ip ssh version 2", start=n) for n in (1, 2, 3)]
    facts = [CiscoSecurityFactMapper().map(c) for c in commands]
    assert [fact.value for fact in facts] == [2, 2, 2]
    assert [fact.evidence.line_start for fact in facts] == [1, 2, 3]


def test_parent_context_and_command_evidence_are_preserved():
    command = parse_cisco_config("line vty 0 4\n transport input ssh\n")[1]
    fact = CiscoSecurityFactMapper().map(command)

    assert fact.parent_context == "line vty 0 4"
    assert fact.evidence.line_start == fact.evidence.line_end == 2
    assert fact.evidence.exact_text == "transport input ssh"


@pytest.mark.parametrize(
    ("raw", "protocols"),
    [
        ("transport input ssh", ["ssh"]),
        ("transport input telnet", ["telnet"]),
        ("transport input telnet ssh", ["telnet", "ssh"]),
    ],
)
def test_vty_transport_mapping_preserves_protocol_order_and_evidence(raw, protocols):
    command = parsed(raw, "line vty 0 4", 22, 23)
    fact = CiscoSecurityFactMapper().map_vty_transport(command)

    assert fact.security_concept == "VTY_TRANSPORT"
    assert fact.property == "allowed_protocols"
    assert fact.value == protocols
    assert fact.parent_context == "line vty 0 4"
    assert fact.evidence.line_start == 22
    assert fact.evidence.line_end == 23
    assert fact.evidence.exact_text == raw
    assert fact.confidence == 1.0
    assert fact.mapping_source == MAPPING_SOURCE


def test_vty_transport_mapping_is_not_emitted_outside_vty_context():
    command = parsed("transport input ssh", "interface GigabitEthernet0/1")

    assert CiscoSecurityFactMapper().map_vty_transport(command) is None


def test_map_commands_preserves_existing_telnet_and_adds_vty_fact():
    command = parsed("transport input telnet ssh", "line vty 0 4")
    facts = CiscoSecurityFactMapper().map_commands(command)

    assert [fact.security_concept for fact in facts] == ["TELNET_ACCESS", "VTY_TRANSPORT"]


def test_map_commands_accepts_actual_parser_output():
    commands = parse_cisco_config("line vty 0 4\n transport input ssh\n")
    facts = CiscoSecurityFactMapper().map_commands(commands)

    assert [(fact.security_concept, fact.property, fact.value) for fact in facts] == [
        ("TELNET_ACCESS", "enabled", False),
        ("VTY_TRANSPORT", "allowed_protocols", ["ssh"]),
    ]


def test_map_commands_accepts_parser_timeout_and_malformed_input():
    mapper = CiscoSecurityFactMapper()
    timeout_facts = mapper.map_commands(parse_cisco_config("ip ssh time-out 60"))
    malformed_facts = mapper.map_commands(parse_cisco_config("ip ssh time-out abc"))

    assert [(fact.security_concept, fact.property, fact.value) for fact in timeout_facts] == [
        ("SSH_TIMEOUT", "timeout_seconds", 60),
    ]
    assert malformed_facts == []


def test_map_commands_ignores_multiple_unrelated_parser_commands():
    commands = parse_cisco_config("hostname R1\nunsupported command\nlogging buffered 64000\n")

    assert CiscoSecurityFactMapper().map_commands(commands) == []


def test_multiline_parser_evidence_preserves_source_text_and_range():
    commands = parse_cisco_config("hostname R1\nbanner login ^\nAUTHORIZED\n^\n")
    banner = commands[1]

    assert banner.line_start == 2
    assert banner.line_end == 4
    assert banner.raw_command == "banner login ^\nAUTHORIZED\n^"


def test_fixture_integration_for_ssh_and_management_security():
    mapper = CiscoSecurityFactMapper()
    root = Path("examples/cisco")
    ssh_facts = [mapper.map(c) for c in parse_cisco_config(root / "02_ssh_variants.cfg")]
    management_facts = [mapper.map(c) for c in parse_cisco_config(root / "03_management_security.cfg")]
    ssh_facts = [f for f in ssh_facts if f]
    management_facts = [f for f in management_facts if f]
    assert {(f.security_concept, f.value) for f in ssh_facts} >= {
        ("SSH_VERSION", 2), ("TELNET_ACCESS", False), ("TELNET_ACCESS", True)
    }
    assert {(f.security_concept, f.value) for f in management_facts} >= {
        ("AAA", "aaa"), ("NTP_AUTHENTICATION", True), ("REMOTE_SYSLOG", True)
    }
