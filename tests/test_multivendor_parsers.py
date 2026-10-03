from parsers.vendors import detect_vendor, get_vendor_parser
from backend.app.normalization.multivendor import map_vendor_commands


def test_all_vendor_parsers_preserve_evidence_and_blank_lines():
    samples = {
        "cisco": "!\nip ssh version 2\n",
        "juniper": "# comment\nset system services ssh protocol-version v2\n",
            "fortinet": "# comment\nconfig system interface\nedit mgmt\nset allowaccess ping ssh https\nnext\nend\n",
        "palo_alto": "// comment\nset deviceconfig system service disable-telnet yes\n",
    }
    for vendor, text in samples.items():
        commands = get_vendor_parser(vendor).parse(text)
        assert commands
        assert commands[0].line_start >= 2
        assert map_vendor_commands(vendor, commands)


def test_unknown_vendor_is_rejected_without_fabricating_parser():
    try:
        get_vendor_parser("unknown")
    except ValueError as exc:
        assert "unsupported vendor" in str(exc)
    else:
        raise AssertionError("unknown vendor should be rejected")


def test_brace_style_junos_normalizes_ssh_and_telnet_with_context():
    text = "system {\n services {\n  ssh {\n   protocol-version v2;\n  }\n  telnet;\n }\n}"
    commands = get_vendor_parser("juniper").parse(text)
    facts = map_vendor_commands("juniper", commands)
    assert {(fact.security_concept, fact.value) for fact in facts} == {("SSH_VERSION", 2), ("TELNET_ACCESS", True)}
    assert all(fact.evidence.line_start > 0 and fact.parent_context for fact in facts)


def test_fortios_detection_and_facts_do_not_use_cisco_controls():
    from backend.app.services import AuditService
    text = "config system interface\n edit mgmt\n  set allowaccess ping ssh https\n next\nend\n"
    assert detect_vendor(text) == "fortinet"
    result = AuditService().audit_config("auto", text)
    assert result.vendor == "fortinet"
    assert all(not finding.rule_id.startswith("CISCO-") for finding in result.findings)
    assert result.posture.score == 95  # SSH is unresolved; unsupported Cisco rules are excluded.


def test_unknown_auto_detection_is_not_a_cisco_fallback():
    from backend.app.services import AuditService
    try:
        AuditService().audit_config("auto", "hostname not enough\n")
    except ValueError as exc:
        assert "unique supported vendor" in str(exc)
    else:
        raise AssertionError("ambiguous auto detection should fail safely")
