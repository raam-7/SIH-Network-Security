from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from backend.app.db import get_session
from backend.app.db.base import Base
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
