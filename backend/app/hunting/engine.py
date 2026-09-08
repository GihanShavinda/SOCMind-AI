"""Threat hunting workspace (Section 8.4).

Ad-hoc, hypothesis-driven querying over normalised events with a small, SAFE
filter language (no raw SQL from the user). A successful hunt can be promoted
into a Sigma-style detection rule (detection-as-code), closing the loop from
hunt → durable detection.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Event
from app.models.common import utcnow

# Fields a hunter may filter on (whitelist — prevents arbitrary access).
ALLOWED_FIELDS = {"event_type", "source_ip", "username", "severity"}
ALLOWED_OPS = {"eq", "contains"}


def run_hunt(db: Session, filters: list[dict], hours: int = 168,
             limit: int = 500) -> dict:
    """Run a hunt. `filters` is a list of {field, op, value}. Returns matching
    events plus a small aggregation to help spot patterns."""
    since = utcnow() - timedelta(hours=hours)
    q = db.query(Event).filter(Event.timestamp >= since)

    applied: list[dict] = []
    for f in filters:
        field, op, value = f.get("field"), f.get("op", "eq"), f.get("value")
        if field not in ALLOWED_FIELDS or op not in ALLOWED_OPS:
            continue
        col = getattr(Event, field)
        if op == "eq":
            q = q.filter(col == value)
        elif op == "contains":
            q = q.filter(col.ilike(f"%{value}%"))
        applied.append({"field": field, "op": op, "value": value})

    rows = q.order_by(Event.timestamp.desc()).limit(limit).all()

    # Aggregate by source_ip and event_type to surface clusters.
    by_ip: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for e in rows:
        if e.source_ip:
            by_ip[e.source_ip] = by_ip.get(e.source_ip, 0) + 1
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1

    return {
        "applied_filters": applied,
        "match_count": len(rows),
        "top_source_ips": sorted(by_ip.items(), key=lambda x: -x[1])[:10],
        "by_event_type": by_type,
        "events": [
            {"id": e.id, "timestamp": e.timestamp.isoformat(),
             "event_type": e.event_type, "source_ip": e.source_ip,
             "username": e.username, "severity": e.severity.value}
            for e in rows[:100]
        ],
    }


def hunt_to_sigma(name: str, filters: list[dict],
                  count: int = 5, window_seconds: int = 120) -> str:
    """Promote a hunt into a Sigma-style YAML rule (detection-as-code, 8.4).
    Returns the YAML text the analyst can drop into detection-rules/."""
    event_type = next((f["value"] for f in filters if f.get("field") == "event_type"), "authentication_failure")
    rule_id = name.lower().replace(" ", "_")
    return (
        f"id: {rule_id}\n"
        f"title: {name}\n"
        f"event_type: {event_type}\n"
        f"severity: medium\n"
        f"mitre: T1110\n"
        f'incident_title: "{name} from {{source_ip}}"\n'
        f"correlation:\n"
        f"  type: threshold\n"
        f"  count: {count}\n"
        f"  window_seconds: {window_seconds}\n"
        f"  group_by: [asset_id, source_ip]\n"
        f"# Promoted from a saved hunt on {datetime.utcnow().date()}\n"
    )
