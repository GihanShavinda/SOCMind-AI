#!/usr/bin/env python3
"""SOCMind AI — Linux auth.log collector.

Runs ON the monitored Ubuntu VM. Tails /var/log/auth.log, parses SSH auth
events, normalises them into the unified event schema, and POSTs them to the
backend ingest endpoint. Keep the collector dumb: all detection lives server-side.

Usage:
    python3 authlog_collector.py \
        --backend http://192.168.56.1:8000 \
        --asset UBUNTU-SERVER-01 \
        --logfile /var/log/auth.log

Requires: pip install requests
"""
import argparse
import re
import time
from datetime import datetime, timezone

import requests

# Examples:
#  "Failed password for invalid user admin from 192.168.56.66 port 55123 ssh2"
#  "Failed password for root from 192.168.56.66 port 55123 ssh2"
#  "Accepted password for ubuntu from 192.168.56.66 port 55124 ssh2"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_RE = re.compile(
    r"Accepted \S+ for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


def build_event(asset: str, event_type: str, ip: str, user: str, raw: str, severity: str):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "asset": asset,
        "event_type": event_type,
        "source_ip": ip,
        "username": user,
        "severity": severity,
        "raw_ref": raw.strip(),
    }


def parse_line(asset: str, line: str):
    m = FAILED_RE.search(line)
    if m:
        return build_event(asset, "authentication_failure",
                           m.group("ip"), m.group("user"), line, "medium")
    m = ACCEPTED_RE.search(line)
    if m:
        return build_event(asset, "authentication_success",
                           m.group("ip"), m.group("user"), line, "low")
    return None


def tail(path: str):
    """Generator that yields new lines appended to the file (like tail -f)."""
    with open(path, "r", errors="ignore") as f:
        f.seek(0, 2)  # jump to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", default="http://localhost:8000")
    ap.add_argument("--asset", required=True, help="hostname registered in SOCMind")
    ap.add_argument("--logfile", default="/var/log/auth.log")
    args = ap.parse_args()

    ingest_url = f"{args.backend.rstrip('/')}/api/events/ingest"
    print(f"[collector] tailing {args.logfile} -> {ingest_url} as {args.asset}")

    for line in tail(args.logfile):
        event = parse_line(args.asset, line)
        if not event:
            continue
        try:
            r = requests.post(ingest_url, json=event, timeout=5)
            result = r.json()
            note = f" [DETECTION: {result['detection']}]" if result.get("detection") else ""
            print(f"[collector] sent {event['event_type']} from {event['source_ip']}{note}")
        except Exception as exc:  # noqa: BLE001
            print(f"[collector] send failed: {exc}")


if __name__ == "__main__":
    main()
