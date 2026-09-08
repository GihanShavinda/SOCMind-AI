"""Phase 4: AI assistant, command recommendation, and safety engine tests."""
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine
from app.startup import seed
from app.detection.engine import reload_rules
from app.ai.catalog import load_catalog
from app.ai import safety


def setup_module(_):
    Base.metadata.create_all(engine); seed(); reload_rules(); load_catalog()


client = TestClient(app)
BASE = datetime(2026, 9, 7, 3, 0, 0, tzinfo=timezone.utc)


def _login():
    r = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _ingest(**kw):
    kw.setdefault("asset", "UBUNTU-SERVER-01")
    kw["timestamp"] = kw.pop("ts").isoformat()
    return client.post("/api/events/ingest", json=kw).json()


def _make_incident():
    for i in range(5):
        _ingest(ts=BASE + timedelta(seconds=i*4), event_type="authentication_failure",
                source_ip="10.4.4.4", username="root", severity="medium")
    return _ingest(ts=BASE + timedelta(seconds=40), event_type="authentication_success",
                   source_ip="10.4.4.4", username="root", severity="low")["incident_id"]


def test_analysis_is_structured_and_grounded():
    iid = _make_incident()
    a = client.get(f"/api/incidents/{iid}/analysis", headers=_login()).json()
    assert a["what_happened"] and a["why_suspicious"]
    assert len(a["next_steps"]) >= 1
    assert a["grounded_on"]                       # every claim is traceable
    assert a["source"] == "rule-based"            # LLM disabled by default


def test_commands_are_os_aware_and_approved():
    iid = _make_incident()
    cmds = client.get(f"/api/incidents/{iid}/commands", headers=_login()).json()
    assert cmds                                    # some recommended
    assert all(c["os"] == "linux" for c in cmds)   # FR-26 (Ubuntu asset)
    assert all(c["risk"] in ("Low", "Medium", "High", "Restricted") for c in cmds)  # FR-27


def test_safety_flags_destructive_as_restricted():
    # FR-29 guardrail: a destructive pattern forces Restricted, never auto-run.
    assert safety.classify("rm -rf /", "Low") == "Restricted"
    assert safety.may_autoexecute("Restricted") is False
    assert safety.may_autoexecute("Low") is True


def test_unknown_command_id_rejected():
    # FR-28: only catalog commands are valid.
    assert safety.validate_command_id("not_a_real_command") is None
