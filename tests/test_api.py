from fastapi.testclient import TestClient

from backend.app.main import app


client = TestClient(app)


def test_health_still_works():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_cisco_audit_api_returns_pass():
    response = client.post(
        "/api/v1/audit/cisco",
        json={"configuration": "hostname R1\nip ssh version 2\n"},
    )

    assert response.status_code == 200
    assert response.json()["findings"][0]["result"] == "PASS"


def test_cisco_audit_api_returns_fail_and_remediation():
    response = client.post(
        "/api/v1/audit/cisco",
        json={"configuration": "ip ssh version 1\n"},
    )

    body = response.json()
    assert response.status_code == 200
    assert body["findings"][0]["result"] == "FAIL"
    assert body["findings"][0]["remediation"] == "ip ssh version 2"


def test_cisco_audit_api_returns_manual_for_missing_ssh_version():
    response = client.post(
        "/api/v1/audit/cisco",
        json={"configuration": "hostname R1\n"},
    )

    assert response.status_code == 200
    assert response.json()["findings"][0]["result"] == "MANUAL"


def test_cisco_audit_api_validates_missing_configuration():
    response = client.post("/api/v1/audit/cisco", json={})

    assert response.status_code == 422


def test_cisco_audit_api_rejects_whitespace_configuration():
    response = client.post("/api/v1/audit/cisco", json={"configuration": "  \n"})

    assert response.status_code == 400
