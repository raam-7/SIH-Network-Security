"""Deterministic defensive attack-path modeling from compliance findings."""
from collections import defaultdict
from backend.app.schemas import Finding, FindingResult, FindingSeverity
from backend.app.schemas.attack_scenario import AttackScenario, AttackScenarioStatus

TAXONOMY = {
    "UNAUTHORIZED_REMOTE_ACCESS": ("Unauthorized Remote Access", "Potential unauthorized access to the network device management plane."),
    "MANAGEMENT_PLANE_EXPOSURE": ("Management Plane Exposure", "Potential exposure of administrative services or management interfaces."),
    "CREDENTIAL_ATTACK": ("Credential Attack", "Potential compromise of management credentials through exposed or weak authentication controls."),
    "CONFIGURATION_TAMPERING": ("Configuration Tampering", "Potential unauthorized modification of device configuration after access is obtained."),
}
MAPPINGS = {
    "CISCO-TELNET-001": {"UNAUTHORIZED_REMOTE_ACCESS", "MANAGEMENT_PLANE_EXPOSURE"},
    "CISCO-VTY-SSH-001": {"UNAUTHORIZED_REMOTE_ACCESS", "MANAGEMENT_PLANE_EXPOSURE"},
    "CISCO-AAA-001": {"CREDENTIAL_ATTACK"},
    "CISCO-SSH-001": {"MANAGEMENT_PLANE_EXPOSURE"},
    "CISCO-SSH-TIMEOUT-001": {"MANAGEMENT_PLANE_EXPOSURE"},
}
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def build_attack_scenarios(findings: list[Finding]) -> list[AttackScenario]:
    grouped = defaultdict(list)
    for finding in findings:
        result = FindingResult(finding.result)
        if result != FindingResult.PASS:
            for scenario_id in MAPPINGS.get(finding.rule_id, set()):
                grouped[scenario_id].append(finding)
    scenarios = []
    for scenario_id, supports in sorted(grouped.items()):
        failed = [f for f in supports if FindingResult(f.result) == FindingResult.FAIL]
        status = AttackScenarioStatus.APPLICABLE if failed else AttackScenarioStatus.POTENTIAL
        severity = max((f.severity.value for f in supports), key=lambda value: SEVERITY_ORDER[value])
        evidence = [f.evidence for f in supports if f.evidence.exact_text.strip()]
        scores = [f.evidence_score for f in supports]
        scenarios.append(AttackScenario(
            scenario_id=scenario_id, name=TAXONOMY[scenario_id][0], description=TAXONOMY[scenario_id][1],
            status=status, severity=severity, supporting_rule_ids=[f.rule_id for f in supports], evidence=evidence,
            evidence_score=max(scores, default=0), requires_human_review=any(FindingResult(f.result) == FindingResult.MANUAL for f in supports),
            potential_path=["External Actor", "Management Plane", "Weak Control", "Potential Device Access", "Configuration Impact"],
            potential_impact=TAXONOMY[scenario_id][1], recommended_controls=[f.remediation for f in supports if f.remediation],
        ))
    return scenarios
