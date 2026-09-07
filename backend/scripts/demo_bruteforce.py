#!/usr/bin/env python3
"""Simulate an SSH brute force against the running backend — no VM needed.

Posts several failed logins followed by a success, then prints the incident that
the detection engine correlated. Run while `docker compose up` is running:

    pip install requests
    python backend/scripts/demo_bruteforce.py
"""
import sys
from datetime import datetime, timezone, timedelta

import requests

BACKEND = "http://localhost:8000"
ASSET = "UBUNTU-SERVER-01"
ATTACKER_IP = "192.168.56.66"
ADMIN = {"username": "admin@socmind.io", "password": "ChangeMe123!"}


def main():
    base = datetime.now(timezone.utc)

    for i in range(7):
        event = {
            "timestamp": (base + timedelta(seconds=i * 8)).isoformat(),
            "asset": ASSET,
            "event_type": "authentication_failure",
            "source_ip": ATTACKER_IP,
            "username": "root",
            "severity": "medium",
        }
        r = requests.post(f"{BACKEND}/api/events/ingest", json=event, timeout=5)
        print(f"failed login {i+1}: {r.json()}")

    # A successful login after the failures — the classic escalation signal.
    success = {
        "timestamp": (base + timedelta(seconds=80)).isoformat(),
        "asset": ASSET,
        "event_type": "authentication_success",
        "source_ip": ATTACKER_IP,
        "username": "root",
        "severity": "low",
    }
    requests.post(f"{BACKEND}/api/events/ingest", json=success, timeout=5)

    # Log in and show the resulting incident + audit trail.
    tok = requests.post(f"{BACKEND}/api/auth/login", data=ADMIN, timeout=5)
    if tok.status_code != 200:
        print("Login failed — is the backend seeded and running?")
        sys.exit(1)
    headers = {"Authorization": f"Bearer {tok.json()['access_token']}"}

    print("\n=== Incidents ===")
    for inc in requests.get(f"{BACKEND}/api/incidents", headers=headers).json():
        print(inc)

    print("\n=== Audit trail ===")
    for a in requests.get(f"{BACKEND}/api/audit", headers=headers).json():
        print(f"{a['timestamp']}  {a['actor']}  {a['action']}  {a['target']}")


if __name__ == "__main__":
    main()
