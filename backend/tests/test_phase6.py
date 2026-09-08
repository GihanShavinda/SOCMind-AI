"""Phase 6: enrichment, reporting/export, MFA."""
import time
from datetime import datetime, timezone, timedelta

from fastapi.testclient import TestClient

from app.main import app
from app.core.database import Base, engine
from app.startup import seed
from app.detection.engine import reload_rules
from app.ai.catalog import load_catalog
from app.response.playbooks import load_playbooks
from app.intel.enrichment import load_iocs, enrich_ip
from app.core import totp


def setup_module(_):
    Base.metadata.create_all(engine); seed()
    reload_rules(); load_catalog(); load_playbooks(); load_iocs()


client = TestClient(app)
BASE = datetime(2026, 9, 7, 3, 0, 0, tzinfo=timezone.utc)


def _admin():
    t = client.post("/api/auth/login",
                    data={"username": "admin@socmind.io", "password": "ChangeMe123!"}).json()
    return {"Authorization": f"Bearer {t['access_token']}"}


def _incident(ip="203.0.113.7"):
    for i in range(5):
        client.post("/api/events/ingest", json={
            "timestamp": (BASE + timedelta(seconds=i*4)).isoformat(),
            "asset": "UBUNTU-SERVER-01", "event_type": "authentication_failure",
            "source_ip": ip, "username": "root", "severity": "medium"})
    r = client.post("/api/events/ingest", json={
        "timestamp": (BASE + timedelta(seconds=40)).isoformat(),
        "asset": "UBUNTU-SERVER-01", "event_type": "authentication_success",
        "source_ip": ip, "username": "root", "severity": "low"})
    return r.json()["incident_id"]


def test_enrichment_flags_ioc_and_private():
    assert enrich_ip("203.0.113.7")["reputation"] == "malicious"   # in IOC feed
    assert enrich_ip("192.168.1.10")["reputation"] == "internal"   # RFC1918
    assert enrich_ip("8.8.8.8")["reputation"] == "unknown"


def test_report_json_has_all_sections():
    iid = _incident()
    r = client.get(f"/api/incidents/{iid}/report", headers=_admin()).json()
    for key in ("incident", "assessment", "attack_story", "kill_chain",
                "evidence", "decisions", "actions", "audit"):
        assert key in r


def test_report_csv_and_pdf():
    iid = _incident()
    csv = client.get(f"/api/incidents/{iid}/report.csv", headers=_admin())
    assert csv.status_code == 200 and "Incident Report" in csv.text
    pdf = client.get(f"/api/incidents/{iid}/report.pdf", headers=_admin())
    assert pdf.status_code == 200 and pdf.content[:5] == b"%PDF-"


def test_mfa_setup_enable_and_login_gate():
    h = _admin()
    secret = client.post("/api/auth/mfa/setup", headers=h).json()["secret"]
    code = totp._hotp(secret, int(time.time() // 30))
    en = client.post("/api/auth/mfa/enable", headers=h, json={"code": code})
    assert en.status_code == 200 and en.json()["mfa_enabled"] is True
    # login without otp is now blocked
    no = client.post("/api/auth/login",
                     data={"username": "admin@socmind.io", "password": "ChangeMe123!"})
    assert no.status_code == 401
    # with a valid otp it works
    code2 = totp._hotp(secret, int(time.time() // 30))
    ok = client.post("/api/auth/login",
                     data={"username": "admin@socmind.io", "password": "ChangeMe123!", "otp": code2})
    assert ok.status_code == 200
    # cleanup: disable so other test modules' admin login still works
    code3 = totp._hotp(secret, int(time.time() // 30))
    client.post("/api/auth/mfa/disable", headers=h, json={"code": code3})
