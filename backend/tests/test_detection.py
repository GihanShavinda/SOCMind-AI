"""Detection engine tests — Phase 1 brute force + Phase 2 layered scenarios.

Run (from backend/):  DATABASE_URL="sqlite+pysqlite:///./test.db" pytest -q
"""
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine
from app.startup import seed
from app.detection.engine import reload_rules


def setup_module(_):
    Base.metadata.create_all(engine)
    seed()
    reload_rules()


client = TestClient(app)
BASE = datetime(2026, 9, 7, 3, 0, 0, tzinfo=timezone.utc)


def _login():
    r = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _ingest(**kw):
    kw.setdefault("asset", "UBUNTU-SERVER-01")
    return client.post("/api/events/ingest", json={
        "timestamp": kw.pop("ts").isoformat(), **kw}).json()


def test_bruteforce_then_escalation():
    for i in range(5):
        _ingest(ts=BASE + timedelta(seconds=i * 5),
                event_type="authentication_failure",
                source_ip="10.1.1.1", username="root", severity="medium")
    r = _ingest(ts=BASE + timedelta(seconds=40),
                event_type="authentication_success",
                source_ip="10.1.1.1", username="root", severity="low")
    assert r["incident_id"] is not None
    inc = client.get(f"/api/incidents/{r['incident_id']}", headers=_login()).json()
    assert inc["severity"] == "critical"          # escalated
    story = client.get(f"/api/incidents/{r['incident_id']}/story",
                       headers=_login()).json()
    assert len(story) >= 2                          # brute force + compromise
    assert any(s["mitre_id"] == "T1078" for s in story)


def test_port_scan_distinct_ports():
    last = None
    for p in range(12):
        last = _ingest(ts=BASE + timedelta(minutes=5, seconds=p),
                       event_type="network_connection",
                       source_ip="10.2.2.2", attributes={"dest_port": 1000 + p})
    assert last["incident_id"] is not None


def test_single_event_rules():
    r = _ingest(ts=BASE + timedelta(minutes=10), event_type="suspicious_process",
                username="ubuntu", attributes={"process_name": "nc -e /bin/bash"})
    assert r["incident_id"] is not None
    r2 = _ingest(ts=BASE + timedelta(minutes=11), event_type="outbound_connection",
                 attributes={"dest_ip": "185.234.1.9", "dest_port": 4444})
    assert r2["incident_id"] is not None


def test_anomaly_new_ip_offhours():
    h = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    for d in range(4):
        _ingest(ts=h + timedelta(days=d), event_type="authentication_success",
                source_ip="192.168.56.10", username="bob", severity="low")
    r = _ingest(ts=BASE + timedelta(minutes=20),
                event_type="authentication_success",
                source_ip="203.0.113.7", username="bob", severity="low")
    assert r["incident_id"] is not None


def test_single_failure_no_incident():
    r = _ingest(ts=BASE + timedelta(minutes=30),
                event_type="authentication_failure",
                source_ip="10.9.9.9", username="root", severity="medium")
    assert r["incident_id"] is None
