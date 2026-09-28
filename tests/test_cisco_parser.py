from pathlib import Path

import pytest

from backend.app.schemas.parsed_command import ParsedCommand as CanonicalParsedCommand
from backend.app.parsers.cisco import parse_cisco_config as backend_parse_cisco_config
from parsers.cisco import CiscoParser, parse_cisco_config
from parsers.cisco.models import ParsedCommand


FIXTURE_DIR = Path(__file__).resolve().parents[1] / "examples" / "cisco"


def parse(config: str):
    return CiscoParser().parse(config)


def command(commands, raw_command: str):
    return next(item for item in commands if item.raw_command == raw_command)


def test_canonical_parsed_command_model_identity():
    assert ParsedCommand is CanonicalParsedCommand
    assert backend_parse_cisco_config is parse_cisco_config


def test_global_command_has_no_parent_context():
    parsed = parse("ip ssh version 2\n")
    assert parsed == [ParsedCommand(raw_command="ip ssh version 2", line_start=1, line_end=1)]


def test_comments_and_blanks_preserve_physical_line_numbers():
    parsed = parse("! separator\n\n ip ignored?\n! another\nip ssh version 2\n")
    assert [item.raw_command for item in parsed] == ["ip ignored?", "ip ssh version 2"]
    assert [(item.line_start, item.parent_context) for item in parsed] == [(3, None), (5, None)]


def test_interface_context_is_assigned_to_child_commands():
    parsed = parse("interface GigabitEthernet0/0\n description UPLINK\n no shutdown\n")
    assert parsed[0].parent_context is None
    assert [(item.raw_command, item.parent_context) for item in parsed[1:]] == [
        ("description UPLINK", "interface GigabitEthernet0/0"),
        ("no shutdown", "interface GigabitEthernet0/0"),
    ]


def test_vty_context_is_assigned_to_child_commands():
    parsed = parse("line vty 0 4\n login local\n transport input ssh\n")
    assert [item.parent_context for item in parsed] == [None, "line vty 0 4", "line vty 0 4"]


def test_bgp_address_family_creates_nested_context():
    parsed = parse(
        "router bgp 65001\n address-family ipv4\n  network 192.0.2.0 mask 255.255.255.0\n"
    )
    assert [(item.raw_command, item.parent_context) for item in parsed] == [
        ("router bgp 65001", None),
        ("address-family ipv4", "router bgp 65001"),
        ("network 192.0.2.0 mask 255.255.255.0", "address-family ipv4"),
    ]


def test_exit_is_emitted_before_its_context_is_popped():
    parsed = parse("interface Loopback0\n description MGMT\n exit\nip ssh version 2\n")
    assert [(item.raw_command, item.parent_context) for item in parsed] == [
        ("interface Loopback0", None),
        ("description MGMT", "interface Loopback0"),
        ("exit", "interface Loopback0"),
        ("ip ssh version 2", None),
    ]


def test_exit_address_family_returns_to_router_context():
    parsed = parse(
        "router bgp 65001\n address-family ipv4\n  neighbor 192.0.2.2 activate\n"
        " exit-address-family\n neighbor 192.0.2.2 remote-as 65002\n"
    )
    assert [(item.raw_command, item.parent_context) for item in parsed[2:]] == [
        ("neighbor 192.0.2.2 activate", "address-family ipv4"),
        ("exit-address-family", "address-family ipv4"),
        ("neighbor 192.0.2.2 remote-as 65002", "router bgp 65001"),
    ]


def test_end_is_emitted_without_parent_and_clears_context():
    parsed = parse("line vty 0 4\n login local\nend\nip ssh version 2\n")
    assert [(item.raw_command, item.parent_context) for item in parsed] == [
        ("line vty 0 4", None), ("login local", "line vty 0 4"),
        ("end", None), ("ip ssh version 2", None),
    ]


def test_no_commands_are_preserved_verbatim():
    parsed = parse("no ip http server\nno cdp run\nno ip source-route\n")
    assert [item.raw_command for item in parsed] == [
        "no ip http server", "no cdp run", "no ip source-route"
    ]


def test_repeated_commands_and_sections_are_not_deduplicated():
    parsed = parse("ip ssh version 2\nip ssh version 1\nip ssh version 2\nline vty 0 4\n exit\nline vty 0 4\n exit\n")
    assert [item.raw_command for item in parsed].count("ip ssh version 2") == 2
    assert [item.raw_command for item in parsed].count("line vty 0 4") == 2
    assert [item.raw_command for item in parsed].count("exit") == 2


def test_caret_delimited_multiline_banner_preserves_range_and_content():
    parsed = parse("banner login ^\nAUTHORIZED USERS ONLY\n^\nip ssh version 2\n")
    banner = parsed[0]
    assert (banner.line_start, banner.line_end) == (1, 3)
    assert banner.raw_command == "banner login ^\nAUTHORIZED USERS ONLY\n^"
    assert parsed[1].line_start == 4


def test_hash_delimited_multiline_banner_preserves_range_and_content():
    banner = parse("banner motd #\nCorporate Network Device\n#\n")[0]
    assert (banner.line_start, banner.line_end) == (1, 3)
    assert banner.raw_command == "banner motd #\nCorporate Network Device\n#"


def test_single_line_banner_remains_a_single_command():
    banner = parse("banner motd ^Maintenance window^\n")[0]
    assert (banner.raw_command, banner.line_start, banner.line_end) == (
        "banner motd ^Maintenance window^", 1, 1
    )


def test_unknown_syntax_is_preserved_without_crashing():
    parsed = parse("vendor-extension alpha beta\n odd nested setting\n")
    assert [item.raw_command for item in parsed] == ["vendor-extension alpha beta", "odd nested setting"]
    assert all(item.parser_status == "parsed" for item in parsed)


def test_tacacs_and_radius_contexts_are_recognized():
    parsed = parse(
        "tacacs server TACACS-PRIMARY\n address ipv4 192.0.2.20\n"
        "radius server RADIUS-PRIMARY\n address ipv4 198.51.100.20\n"
    )
    assert [(item.raw_command, item.parent_context) for item in parsed] == [
        ("tacacs server TACACS-PRIMARY", None),
        ("address ipv4 192.0.2.20", "tacacs server TACACS-PRIMARY"),
        ("radius server RADIUS-PRIMARY", None),
        ("address ipv4 198.51.100.20", "radius server RADIUS-PRIMARY"),
    ]


def test_acl_context_is_recognized():
    parsed = parse("ip access-list extended VTY-MGMT\n permit tcp any any eq 22\n deny ip any any log\n")
    assert [item.parent_context for item in parsed] == [
        None, "ip access-list extended VTY-MGMT", "ip access-list extended VTY-MGMT"
    ]


@pytest.mark.parametrize(
    ("filename", "expected_count", "last_line", "expected_command", "expected_parent"),
    [
        ("01_enterprise_secure.cfg", 63, 89, "transport input ssh", "line vty 0 4"),
        ("02_ssh_variants.cfg", 21, 45, "transport input telnet", "line vty 5 15"),
        ("03_management_security.cfg", 37, 57, "transport input ssh", "line vty 0 4"),
        ("04_routing_acl_hierarchy.cfg", 46, 62, "neighbor 192.0.2.2 activate", "address-family ipv4"),
        ("05_management_services.cfg", 46, 72, "no ip source-route", None),
        ("06_parser_edge_cases.cfg", 40, 84, "exit-address-family", "address-family ipv4"),
    ],
)
def test_synthetic_cisco_fixture_regressions(
    filename, expected_count, last_line, expected_command, expected_parent
):
    parsed = parse_cisco_config(FIXTURE_DIR / filename)
    assert len(parsed) == expected_count
    assert parsed[0].line_start == 7
    assert parsed[-1].raw_command == "end"
    assert parsed[-1].line_start == last_line
    assert command(parsed, expected_command).parent_context == expected_parent
