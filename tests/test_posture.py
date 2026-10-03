from backend.app.services import AuditService
from backend.app.services.posture import calculate_posture
from backend.app.schemas import FindingResult


def test_posture_is_deterministic_bounded_and_explained():
    findings = AuditService().audit_cisco_config("ip ssh version 1\n").findings
    first = calculate_posture(findings)
    second = calculate_posture(findings)
    assert first == second
    assert 0 <= first.score <= 100
    assert first.manual > 0 and first.deductions
    assert "starts at 100" in first.explanation


def test_clean_configuration_has_full_score():
    findings = AuditService().audit_cisco_config("aaa new-model\nip ssh version 2\nip ssh time-out 60\nline vty 0 4\n transport input ssh\n").findings
    assert calculate_posture(findings).score == 100
