from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
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
    assert listed.json()


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
    assert client.get("/api/v1/audits").json() == []


def test_history_is_lightweight_and_contains_summary_fields():
    audit_id = create_persisted_audit()
    item = client.get("/api/v1/audits").json()[0]

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
    assert [item["audit_id"] for item in listed] == [second, first]
    assert [item["audit_id"] for item in client.get("/api/v1/audits?limit=1").json()] == [second]
    assert [item["audit_id"] for item in client.get("/api/v1/audits?offset=1").json()] == [first]


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

    assert [item["audit_id"] for item in client.get("/api/v1/audits?vendor=cisco").json()] == [
        non_compliant, review_required, compliant
    ]
    assert [item["audit_id"] for item in client.get("/api/v1/audits?platform=ios-xe").json()] == [
        non_compliant, review_required, compliant
    ]
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?overall_status=COMPLIANT"
    ).json()] == [compliant]
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?overall_status=NON_COMPLIANT"
    ).json()] == [non_compliant]
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?overall_status=REVIEW_REQUIRED"
    ).json()] == [review_required]
    assert [item["audit_id"] for item in client.get(
        "/api/v1/audits?vendor=cisco&platform=ios-xe&overall_status=COMPLIANT"
    ).json()] == [compliant]


def test_history_filters_apply_before_pagination_and_support_no_matches():
    first = create_persisted_audit("ip ssh version 1\n")
    second = create_persisted_audit("ip ssh version 1\n")
    third = create_persisted_audit("ip ssh version 1\n")

    filtered = client.get("/api/v1/audits?vendor=cisco&limit=1&offset=1")
    assert filtered.status_code == 200
    assert [item["audit_id"] for item in filtered.json()] == [second]
    assert client.get("/api/v1/audits?vendor=juniper").json() == []
    assert client.get("/api/v1/audits?vendor=cisco&platform=junos").json() == []
    assert {item["audit_id"] for item in client.get("/api/v1/audits").json()} == {
        first, second, third
    }


def test_history_rejects_invalid_status_filter_and_empty_filtered_history():
    assert client.get("/api/v1/audits?overall_status=UNKNOWN").status_code == 422
    assert client.get("/api/v1/audits?vendor=cisco").json() == []
