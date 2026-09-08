"""Phase 7: triage/SLA, RAG knowledge base, feedback + active learning."""
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine
from app.startup import seed
from app.detection.engine import reload_rules
from app.ai.catalog import load_catalog
from app.response.playbooks import load_playbooks
from app.intel.enrichment import load_iocs


def setup_module(_):
    Base.metadata.create_all(engine); seed()
    reload_rules(); load_catalog(); load_playbooks(); load_iocs()


client = TestClient(app)


def _h():
    t = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"}).json()
    return {"Authorization": f"Bearer {t['access_token']}"}


def _brute(ip, hour):
    base = datetime(2026, 9, 7, hour, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        client.post("/api/events/ingest", json={
            "timestamp": (base + timedelta(seconds=i*4)).isoformat(),
            "asset": "UBUNTU-SERVER-01", "event_type": "authentication_failure",
            "source_ip": ip, "username": "root", "severity": "medium"})
    r = client.post("/api/events/ingest", json={
        "timestamp": (base + timedelta(seconds=40)).isoformat(),
        "asset": "UBUNTU-SERVER-01", "event_type": "authentication_success",
        "source_ip": ip, "username": "root", "severity": "low"})
    return r.json()["incident_id"]


def test_triage_and_sla_present():
    _brute("10.1.1.1", 3)
    incidents = client.get("/api/incidents", headers=_h()).json()
    assert incidents
    top = incidents[0]
    assert top["triage_score"] > 0
    assert top["sla_due_at"] is not None
    assert "sla_breached" in top


def test_rag_finds_similar_incident():
    a = _brute("10.2.2.2", 4)
    b = _brute("10.3.3.3", 5)          # same technique profile as a
    sim = client.get(f"/api/incidents/{b}/similar", headers=_h()).json()
    assert any(s["id"] == a for s in sim)
    assert sim[0]["shared_techniques"]      # shares MITRE techniques


def test_analysis_grounds_on_similar():
    _brute("10.4.4.4", 6)
    b = _brute("10.5.5.5", 7)
    an = client.get(f"/api/incidents/{b}/analysis", headers=_h()).json()
    assert "similar_incidents" in an
    assert any("similar" in g.lower() for g in an["grounded_on"])


def test_feedback_dismiss_sets_status():
    b = _brute("10.6.6.6", 8)
    fb = client.post(f"/api/incidents/{b}/feedback", headers=_h(),
                     json={"verdict": "dismiss", "note": "false positive"})
    assert fb.status_code == 201
    inc = client.get(f"/api/incidents/{b}", headers=_h()).json()
    assert inc["status"] == "dismissed"


def test_active_learning_adjustment_bounded():
    from app.detection.learning import rule_confidence_adjustment, MAX_ADJUST
    from app.core.database import SessionLocal
    db = SessionLocal()
    adj = rule_confidence_adjustment(db, "ssh_bruteforce")
    db.close()
    assert -MAX_ADJUST <= adj <= MAX_ADJUST      # bounded, never overrides
