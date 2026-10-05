from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def evidence(line=8, text="uncertain command"):
    return {"line_start": line, "line_end": line, "exact_text": text}


def finding(result="MANUAL"):
    return {
        "rule_id": "CISCO-SSH-001",
        "result": result,
        "severity": "MEDIUM",
        "observed_value": None,
        "expected_value": 2,
        "evidence": evidence(),
        "title": "Manual review",
        "description": "Requires human verification",
        "remediation": "Verify manually.",
    }


def review_payload(**overrides):
    payload = {
        "finding": finding(),
        "decision": "COMPLIANT",
        "reviewer": "alice",
        "reviewer_reason": "Verified against approved policy.",
    }
    payload.update(overrides)
    return payload


def test_manual_finding_can_be_reviewed_as_compliant():
    response = client.post("/api/v1/reviews", json=review_payload())

    body = response.json()
    assert response.status_code == 200
    assert len(body["review_id"]) == 36
    assert body["rule_id"] == "CISCO-SSH-001"
    assert body["original_result"] == "MANUAL"
    assert body["decision"] == "COMPLIANT"
    assert body["status"] == "PENDING"
    assert body["evidence_reference"] == evidence()


def test_manual_finding_can_be_reviewed_as_non_compliant():
    response = client.post(
        "/api/v1/reviews", json=review_payload(decision="NON_COMPLIANT")
    )

    assert response.status_code == 200
    assert response.json()["original_result"] == "MANUAL"
    assert response.json()["decision"] == "NON_COMPLIANT"


def test_pass_and_fail_findings_are_rejected():
    for result in ("PASS", "FAIL"):
        response = client.post("/api/v1/reviews", json=review_payload(finding=finding(result)))
        assert response.status_code == 400


def test_invalid_decision_is_rejected_by_schema():
    response = client.post("/api/v1/reviews", json=review_payload(decision="MANUAL"))

    assert response.status_code == 422


def test_empty_reviewer_and_reason_are_rejected():
    for field in ("reviewer", "reviewer_reason"):
        response = client.post("/api/v1/reviews", json=review_payload(**{field: "  "}))
        assert response.status_code == 422


def test_explicit_evidence_overrides_finding_evidence():
    supplied = evidence(20, "reviewer evidence")
    response = client.post(
        "/api/v1/reviews", json=review_payload(evidence_reference=supplied)
    )

    assert response.status_code == 200
    assert response.json()["evidence_reference"] == supplied


def test_invalid_evidence_is_rejected():
    response = client.post(
        "/api/v1/reviews", json=review_payload(evidence_reference={"line_start": 0})
    )

    assert response.status_code == 422
