from backend.app.schemas import Evidence, Finding, FindingResult, FindingSeverity
from backend.app.services.explanation import ExplanationService


def make_finding(result=FindingResult.FAIL, exact_text="ip ssh version 1"):
    return Finding(rule_id="CISCO-SSH-001", result=result, severity=FindingSeverity.MEDIUM,
                   observed_value=1, expected_value=2,
                   evidence=Evidence(line_start=1, line_end=1, exact_text=exact_text),
                   title="SSH version", description="SSH version check", remediation=None,
                   semantic_concept="SSH_VERSION", semantic_property="protocol_version")


def test_deterministic_explanations_cover_pass_fail_and_manual():
    service = ExplanationService()
    for result in (FindingResult.PASS, FindingResult.FAIL, FindingResult.MANUAL):
        explanation = service.explain(make_finding(result), vendor="cisco", platform="ios-xe")
        assert explanation.source == "deterministic-fallback"
        assert "ip ssh version 1" in explanation.evidence_summary
    assert "human review is required" in service.explain(make_finding(FindingResult.MANUAL), vendor="cisco", platform="ios-xe").explanation


def test_provider_failure_malformed_output_and_ungrounded_evidence_fall_back():
    class BrokenProvider:
        def explain(self, _context):
            raise TimeoutError("model unavailable")
    class MalformedProvider:
        def explain(self, _context):
            return {"explanation": "invented", "detected_condition": "invented", "expected_condition": "invented", "evidence_summary": "invented evidence", "explanation_confidence": 0.99, "source": "model"}
    for provider in (BrokenProvider(), MalformedProvider()):
        explanation = ExplanationService(provider).explain(make_finding(), vendor="cisco", platform="ios-xe")
        assert explanation.source == "deterministic-fallback"
        assert "ip ssh version 1" in explanation.evidence_summary


def test_explanation_cannot_change_deterministic_result_or_severity():
    finding = make_finding(FindingResult.FAIL)
    explanation = ExplanationService().explain(finding, vendor="juniper", platform="junos")
    assert finding.result is FindingResult.FAIL
    assert finding.severity is FindingSeverity.MEDIUM
    assert explanation.explanation_confidence <= 1.0
