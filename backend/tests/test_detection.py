"""Example test for the SSH brute-force detection slice.

Run (from backend/):  DATABASE_URL="sqlite+pysqlite:///./test.db" pytest -q
"""
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine
from app.startup import seed


def setup_module(_):
    Base.metadata.create_all(engine)
    seed()


client = TestClient(app)


def _login():
    r = client.post(
        "/api/auth/login",
        data={"username": "admin@socmind.io", "password": "ChangeMe123!"},
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_bruteforce_creates_incident():
    base = datetime.now(timezone.utc)
    last = None
    for i in range(6):
        last = client.post("/api/events/ingest", json={
            "timestamp": (base + timedelta(seconds=i * 10)).isoformat(),
            "asset": "UBUNTU-SERVER-01",
            "event_type": "authentication_failure",
            "source_ip": "10.0.0.9",
            "username": "root",
            "severity": "medium",
        }).json()

    assert last["detection"] == "ssh_bruteforce"
    assert last["incident_id"] is not None

    incidents = client.get("/api/incidents", headers=_login()).json()
    assert any(inc["severity"] == "high" for inc in incidents)


def test_single_failure_no_incident():
    r = client.post("/api/events/ingest", json={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": "UBUNTU-SERVER-01",
        "event_type": "authentication_failure",
        "source_ip": "10.0.0.250",
        "username": "root",
        "severity": "medium",
    }).json()
    assert r["incident_id"] is None
