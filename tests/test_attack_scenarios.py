from backend.app.schemas import Evidence, Finding, FindingResult, FindingSeverity
from backend.app.services.attack_scenarios import build_attack_scenarios

def finding(rule_id: str, result: FindingResult, text: str = "evidence") -> Finding:
    return Finding(rule_id=rule_id, result=result, severity=FindingSeverity.MEDIUM,
                   observed_value=None, expected_value=None,
                   evidence=Evidence(line_start=1, line_end=1, exact_text=text),
                   title=rule_id, description="test", evidence_score=80)

def test_telnet_and_vty_failures_support_remote_access_and_management_exposure():
    scenarios = build_attack_scenarios([
        finding("CISCO-TELNET-001", FindingResult.FAIL),
        finding("CISCO-VTY-SSH-001", FindingResult.FAIL),
    ])
    by_id = {scenario.scenario_id: scenario for scenario in scenarios}
    assert by_id["UNAUTHORIZED_REMOTE_ACCESS"].status.value == "APPLICABLE"
    assert by_id["MANAGEMENT_PLANE_EXPOSURE"].status.value == "APPLICABLE"
    assert set(by_id["UNAUTHORIZED_REMOTE_ACCESS"].supporting_rule_ids) == {"CISCO-TELNET-001", "CISCO-VTY-SSH-001"}

def test_manual_aaa_is_potential_and_requires_review():
    scenarios = build_attack_scenarios([finding("CISCO-AAA-001", FindingResult.MANUAL, "")])
    credential = next(scenario for scenario in scenarios if scenario.scenario_id == "CREDENTIAL_ATTACK")
    assert credential.status.value == "POTENTIAL"
    assert credential.requires_human_review is True
    assert credential.evidence == []

def test_pass_findings_do_not_create_scenarios():
    assert build_attack_scenarios([finding("CISCO-TELNET-001", FindingResult.PASS)]) == []
