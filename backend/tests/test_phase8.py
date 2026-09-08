"""Phase 8: UEBA, threat hunting, forensics/chain-of-custody, model cards."""
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine, SessionLocal
from app.startup import seed
from app.detection.engine import reload_rules
from app.ai.catalog import load_catalog
from app.response.playbooks import load_playbooks
from app.intel.enrichment import load_iocs
from app.forensics.custody import verify_package
from app.models import Incident


def setup_module(_):
    Base.metadata.create_all(engine); seed()
    reload_rules(); load_catalog(); load_playbooks(); load_iocs()


client = TestClient(app)


def _h():
    t = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"}).json()
    return {"Authorization": f"Bearer {t['access_token']}"}


def _incident(ip="203.0.113.7"):
    b = datetime(2026, 9, 7, 3, 0, 0, tzinfo=timezone.utc)
    for i in range(5):
        client.post("/api/events/ingest", json={
            "timestamp": (b + timedelta(seconds=i*4)).isoformat(),
            "asset": "UBUNTU-SERVER-01", "event_type": "authentication_failure",
            "source_ip": ip, "username": "root", "severity": "medium"})
    r = client.post("/api/events/ingest", json={
        "timestamp": (b + timedelta(seconds=40)).isoformat(),
        "asset": "UBUNTU-SERVER-01", "event_type": "authentication_success",
        "source_ip": ip, "username": "root", "severity": "low"})
    return r.json()["incident_id"]


def test_ueba_entity_risk_and_timeline():
    iid = _incident("10.8.8.8")
    ue = client.get("/api/ueba/entity", headers=_h(),
                    params={"entity_type": "ip", "value": "10.8.8.8"}).json()
    assert 0 <= ue["risk_score"] <= 100 and ue["factors"]
    rt = client.get(f"/api/incidents/{iid}/risk-timeline", headers=_h()).json()
    assert len(rt) >= 1
    assert rt[-1]["cumulative_risk"] >= rt[0]["cumulative_risk"]   # monotonic


def test_threat_hunt_and_promote():
    _incident("10.8.8.9")
    hunt = client.post("/api/hunt", headers=_h(), json={
        "filters": [{"field": "event_type", "op": "eq", "value": "authentication_failure"}],
        "hours": 999999}).json()
    assert hunt["match_count"] >= 5
    pr = client.post("/api/hunt/promote", headers=_h(), json={
        "name": "Custom Hunt", "filters": [
            {"field": "event_type", "op": "eq", "value": "authentication_failure"}]}).json()
    assert "id: custom_hunt" in pr["rule_yaml"] and "threshold" in pr["rule_yaml"]


def test_hunt_rejects_unknown_field():
    # SAFE filter language: unknown fields are ignored, not executed as SQL.
    hunt = client.post("/api/hunt", headers=_h(), json={
        "filters": [{"field": "password", "op": "eq", "value": "x"}],
        "hours": 999999}).json()
    assert hunt["applied_filters"] == []          # unsafe field dropped


def test_forensics_case_package_is_tamper_evident():
    iid = _incident("10.8.8.10")
    cp = client.get(f"/api/incidents/{iid}/case-package", headers=_h()).json()
    assert cp["evidence_count"] >= 1 and cp["manifest_sha256"]
    db = SessionLocal(); inc = db.get(Incident, iid)
    assert verify_package(db, inc, cp["manifest_sha256"]) is True
    # a wrong manifest must fail verification
    assert verify_package(db, inc, "deadbeef") is False
    db.close()


def test_model_cards_and_calibration():
    cards = client.get("/api/model-cards", headers=_h()).json()
    assert len(cards) >= 4 and all("failure_modes" in c for c in cards)
    cal = client.get("/api/calibration", headers=_h()).json()
    assert "bands" in cal and len(cal["bands"]) == 3
