from datetime import datetime, timedelta, timezone
from uuid import UUID
import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from backend.app.db import get_session
from backend.app.db.base import Base
from backend.app.db.models import AuditORM, FindingORM, RiskAssessmentORM
from backend.app.main import app


engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)


def override_session():
    session = Session()
    try:
        yield session
    finally:
        session.close()


app.dependency_overrides[get_session] = override_session
client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_database():
    with Session() as session:
        session.query(RiskAssessmentORM).delete()
        session.query(FindingORM).delete()
        session.query(AuditORM).delete()
        session.commit()


def test_persistence_api_create_get_and_list():
    response = client.post("/api/v1/audits", json={"configuration": "ip ssh version 2\n"})
    assert response.status_code == 200
    audit_id = response.json()["audit_id"]

    fetched = client.get(f"/api/v1/audits/{audit_id}")
    listed = client.get("/api/v1/audits")
    assert fetched.status_code == 200
    assert fetched.json()["summary"]["overall_status"] == "REVIEW_REQUIRED"
    assert listed.status_code == 200
    assert listed.json()["items"]


def test_database_error_returns_cors_compatible_service_unavailable(monkeypatch):
    def unavailable_session():
        raise OperationalError("SELECT 1", {}, RuntimeError("database unavailable"))

    monkeypatch.setitem(app.dependency_overrides, get_session, unavailable_session)
    try:
        response = client.get(
            "/api/v1/audits",
            headers={"Origin": "http://localhost:3000"},
        )
    finally:
        app.dependency_overrides[get_session] = override_session

    assert response.status_code == 503
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert response.json()["detail"] == (
        "Database unavailable. Check that PostgreSQL is running and "
        "DATABASE_URL in the root .env file has valid credentials."
    )


def test_api_generates_exact_server_side_configuration_hash_and_round_trips():
    configuration = "ip ssh version 2\n"
    response = client.post("/api/v1/audits", json={"configuration": configuration})
    assert response.status_code == 200
    audit_id = response.json()["audit_id"]
    expected = hashlib.sha256(configuration.encode("utf-8")).hexdigest()

    report = response.json()["report"]
    assert report["configuration_hash"] == expected
    assert len(report["configuration_hash"]) == 64
    assert all(char in "0123456789abcdef" for char in report["configuration_hash"])
    detail = client.get(f"/api/v1/audits/{audit_id}")
    assert detail.json()["configuration_hash"] == expected
    history = client.get("/api/v1/audits").json()
    assert "configuration_hash" not in history["items"][0]


def test_persistence_api_validates_input_and_missing_id():
    assert client.post("/api/v1/audits", json={}).status_code == 422
    assert client.get("/api/v1/audits/00000000-0000-0000-0000-000000000000").status_code == 404


def create_persisted_audit(configuration="ip ssh version 2\n"):
    response = client.post("/api/v1/audits", json={"configuration": configuration})
    assert response.status_code == 200
    return response.json()["audit_id"]


COMPLIANT_CONFIGURATION = (
    "aaa new-model\n"
    "ip ssh version 2\n"
    "ip ssh time-out 60\n"
    "line vty 0 4\n"
    " transport input ssh\n"
)


def test_empty_audit_history_returns_empty_list():
    assert client.get("/api/v1/audits").json() == {
        "items": [],
        "pagination": {"limit": 50, "offset": 0, "total": 0, "has_more": False},
    }


def test_history_is_lightweight_and_contains_summary_fields():
    audit_id = create_persisted_audit()
    response = client.get("/api/v1/audits").json()
    item = response["items"][0]

    assert item["audit_id"] == audit_id
    assert set(item) == {
        "audit_id", "vendor", "platform", "overall_status", "total_controls",
        "passed", "failed", "manual", "informational", "parsed_command_count",
        "security_fact_count", "created_at",
    }
    assert item["vendor"] == "cisco"
    assert item["platform"] == "ios-xe"
    assert item["overall_status"] == "REVIEW_REQUIRED"
    assert item["total_controls"] == 5
    assert item["parsed_command_count"] == 1
    assert item["security_fact_count"] == 1
    assert "findings" not in item
    assert "evidence" not in item
    assert "risk_level" not in item
    assert response["pagination"] == {"limit": 50, "offset": 0, "total": 1, "has_more": False}


def test_history_is_newest_first_and_supports_limit_and_offset():
    first = create_persisted_audit("ip ssh version 1\n")
    second = create_persisted_audit("ip ssh version 2\n")
    with Session() as session:
        first_row = session.get(AuditORM, UUID(first))
        second_row = session.get(AuditORM, UUID(second))
        first_row.created_at = datetime.now(timezone.utc) - timedelta(days=1)
        second_row.created_at = datetime.now(timezone.utc)
        session.commit()

    listed = client.get("/api/v1/audits").json()
    assert [item["audit_id"] for item in listed["items"]] == [second, first]
    assert listed["pagination"] == {"limit": 50, "offset": 0, "total": 2, "has_more": False}
    first_page = client.get("/api/v1/audits?limit=1").json()
    assert [item["audit_id"] for item in first_page["items"]] == [second]
    assert first_page["pagination"] == {"limit": 1, "offset": 0, "total": 2, "has_more": True}
    last_page = client.get("/api/v1/audits?limit=1&offset=1").json()
    assert [item["audit_id"] for item in last_page["items"]] == [first]
    assert last_page["pagination"] == {"limit": 1, "offset": 1, "total": 2, "has_more": False}


def test_history_pagination_validation_and_detail_remain_compatible():
    audit_id = create_persisted_audit()
    assert client.get("/api/v1/audits?limit=0").status_code == 422
    assert client.get("/api/v1/audits?limit=101").status_code == 422
    assert client.get("/api/v1/audits?offset=-1").status_code == 422

    detail = client.get(f"/api/v1/audits/{audit_id}")
    assert detail.status_code == 200
    assert len(detail.json()["findings"]) == 5
    assert "evidence" in detail.json()["findings"][0]
    assert client.get("/api/v1/audits/00000000-0000-0000-0000-000000000000").status_code == 404


def test_history_filters_vendor_platform_and_combined_status():
    compliant = create_persisted_audit(COMPLIANT_CONFIGURATION)
    review_required = create_persisted_audit("ip ssh version 2\n")
    non_compliant = create_persisted_audit("ip ssh version 1\n")

    assert [item["audit_id"] for item in client.get("/api/v1/audits?vendor=cisco").json()["items"]] == [
        non_compliant, review_required, compliant
    ]
    assert [item["audit_id"] for item in client.get("/api/v1/audits?platform=ios-xe").json()["items"]] == [
        non_compliant, review_required, compliant
    ]
    compliant_response = client.get("/api/v1/audits?overall_status=COMPLIANT").json()
    assert [item["audit_id"] for item in compliant_response["items"]] == [compliant]
    assert compliant_response["pagination"]["total"] == 1
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?overall_status=NON_COMPLIANT"
    ).json()["items"]] == [non_compliant]
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?overall_status=REVIEW_REQUIRED"
    ).json()["items"]] == [review_required]
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?vendor=cisco&platform=ios-xe&overall_status=COMPLIANT"
    ).json()["items"]] == [compliant]


def test_history_filters_apply_before_pagination_and_support_no_matches():
    first = create_persisted_audit("ip ssh version 1\n")
    second = create_persisted_audit("ip ssh version 1\n")
    third = create_persisted_audit("ip ssh version 1\n")

    filtered = client.get("/api/v1/audits?vendor=cisco&limit=1&offset=1")
    assert filtered.status_code == 200
    assert [item["audit_id"] for item in filtered.json()["items"]] == [second]
    assert filtered.json()["pagination"] == {"limit": 1, "offset": 1, "total": 3, "has_more": True}
    assert client.get("/api/v1/audits?vendor=juniper").json()["pagination"]["total"] == 0
    assert client.get("/api/v1/audits?vendor=cisco&platform=junos").json()["items"] == []
    assert {item["audit_id"] for item in client.get("/api/v1/audits").json()["items"]} == {
        first, second, third
    }


def test_history_boundary_and_out_of_range_pages_report_has_more_correctly():
    for _ in range(4):
        create_persisted_audit("ip ssh version 1\n")

    exact_boundary = client.get("/api/v1/audits?limit=2&offset=2").json()
    assert len(exact_boundary["items"]) == 2
    assert exact_boundary["pagination"] == {"limit": 2, "offset": 2, "total": 4, "has_more": False}

    out_of_range = client.get("/api/v1/audits?limit=2&offset=10").json()
    assert out_of_range["items"] == []
    assert out_of_range["pagination"] == {"limit": 2, "offset": 10, "total": 4, "has_more": False}


def test_history_rejects_invalid_status_filter_and_empty_filtered_history():
    assert client.get("/api/v1/audits?overall_status=UNKNOWN").status_code == 422
    response = client.get("/api/v1/audits?vendor=cisco").json()
    assert response["items"] == []
    assert response["pagination"]["total"] == 0
    assert response["pagination"]["has_more"] is False
