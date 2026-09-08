"""Phase 5: playbooks, decision engine, actions, approvals, rollback, RBAC."""
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine, SessionLocal
from app.startup import seed
from app.detection.engine import reload_rules
from app.response.playbooks import load_playbooks
from app.core.security import hash_password
from app.models import User, Asset
from app.models.common import Role, Criticality


def setup_module(_):
    Base.metadata.create_all(engine); seed(); reload_rules(); load_playbooks()
    db = SessionLocal()
    # A low-criticality, opted-in asset to exercise the automate path.
    if not db.query(Asset).filter(Asset.hostname == "LAB-LOWCRIT").first():
        db.add(Asset(hostname="LAB-LOWCRIT", os="Ubuntu 22.04", ip="192.168.56.90",
                     environment="lab", criticality=Criticality.LOW,
                     automation_enabled=True, auto_action_types=["create_ticket"]))
    # An analyst (non-admin) to test approval RBAC.
    if not db.query(User).filter(User.email == "analyst@socmind.io").first():
        db.add(User(name="A", email="analyst@socmind.io",
                    password_hash=hash_password("Analyst123!"), role=Role.ANALYST))
    db.commit(); db.close()


client = TestClient(app)
BASE = datetime(2026, 9, 7, 3, 0, 0, tzinfo=timezone.utc)


def _tok(email, pw):
    return client.post("/api/auth/login", data={"username": email, "password": pw}).json()["access_token"]


def _admin():
    return {"Authorization": f"Bearer {_tok('admin@socmind.io','ChangeMe123!')}"}


def _analyst():
    return {"Authorization": f"Bearer {_tok('analyst@socmind.io','Analyst123!')}"}


def _brute_incident(ip="10.5.5.5", asset="UBUNTU-SERVER-01", fails=5):
    for i in range(fails):
        client.post("/api/events/ingest", json={
            "timestamp": (BASE + timedelta(seconds=i*4)).isoformat(), "asset": asset,
            "event_type": "authentication_failure", "source_ip": ip,
            "username": "root", "severity": "medium"})
    r = client.post("/api/events/ingest", json={
        "timestamp": (BASE + timedelta(seconds=fails*4 + 10)).isoformat(), "asset": asset,
        "event_type": "authentication_success", "source_ip": ip,
        "username": "root", "severity": "low"})
    return r.json()["incident_id"]


def test_playbook_selected():
    iid = _brute_incident()
    pb = client.get(f"/api/incidents/{iid}/playbook", headers=_admin()).json()
    assert pb and pb["attack_type"] == "brute_force" and len(pb["steps"]) > 0


def test_high_risk_requires_approval_then_executes_and_rolls_back():
    iid = _brute_incident()
    a = client.post(f"/api/incidents/{iid}/actions", headers=_admin(),
                    json={"action_type": "isolate_endpoint"}).json()
    assert a["status"] == "pending_approval" and a["risk_level"] == "High"
    ap = client.post(f"/api/actions/{a['id']}/approve", headers=_admin()).json()
    assert ap["status"] == "executed" and ap["undo_ref"]        # FR-36 undo ref
    rb = client.post(f"/api/actions/{a['id']}/rollback", headers=_admin()).json()
    assert rb["status"] == "rolled_back"


def test_analyst_cannot_approve_high_risk():
    iid = _brute_incident()
    a = client.post(f"/api/incidents/{iid}/actions", headers=_analyst(),
                    json={"action_type": "isolate_endpoint"}).json()
    r = client.post(f"/api/actions/{a['id']}/approve", headers=_analyst())
    assert r.status_code == 403                                  # FR-3


def test_low_crit_opted_in_automates():
    iid = _brute_incident(ip="10.6.6.6", asset="LAB-LOWCRIT", fails=9)  # high confidence
    a = client.post(f"/api/incidents/{iid}/actions", headers=_admin(),
                    json={"action_type": "create_ticket"}).json()
    assert a["status"] == "executed"                             # auto-executed
    dec = client.get(f"/api/incidents/{iid}/decisions", headers=_admin()).json()[0]
    assert dec["outcome"] == "automate"


def test_high_crit_never_automates_even_if_opted_in():
    # UBUNTU-SERVER-01 is High criticality; opt it in and confirm it still escalates.
    db = SessionLocal()
    asset = db.query(Asset).filter(Asset.hostname == "UBUNTU-SERVER-01").first()
    asset.automation_enabled = True; asset.auto_action_types = ["create_ticket"]
    db.commit(); db.close()
    iid = _brute_incident(ip="10.7.7.7")
    a = client.post(f"/api/incidents/{iid}/actions", headers=_admin(),
                    json={"action_type": "create_ticket"}).json()
    assert a["status"] == "pending_approval"                     # safety invariant
