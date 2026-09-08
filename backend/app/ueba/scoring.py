"""UEBA — User & Entity Behaviour Analytics (Section 8.3).

Computes a risk score for an entity (user, host or source IP) from its recent
activity, and a risk timeline showing how that risk built up across an incident.
Offline and deterministic: risk is derived from stored events, alerts, anomaly
scores and IOC reputation — no external service.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import Event, Alert, Incident
from app.models.common import utcnow


# Per-event-type risk contribution.
_EVENT_RISK = {
    "authentication_failure": 4,
    "authentication_success": 2,
    "network_connection": 3,      # scanning
    "suspicious_process": 12,
    "outbound_connection": 10,
}


def _entity_filter(query, entity_type: str, value: str):
    if entity_type == "user":
        return query.filter(Event.username == value)
    if entity_type == "ip":
        return query.filter(Event.source_ip == value)
    if entity_type == "host":
        # host is an asset hostname → match via asset relationship
        return query.join(Event.asset).filter(Event.asset.has(hostname=value))
    return query


def entity_risk(db: Session, entity_type: str, value: str, days: int = 30) -> dict:
    """Return a 0..100 risk score and its contributing factors for an entity."""
    since = utcnow() - timedelta(days=days)
    q = _entity_filter(db.query(Event).filter(Event.timestamp >= since),
                       entity_type, value)
    events = q.all()

    raw = 0
    factors: list[str] = []
    by_type: dict[str, int] = {}
    for e in events:
        by_type[e.event_type] = by_type.get(e.event_type, 0) + 1
        raw += _EVENT_RISK.get(e.event_type, 1)
        if (e.attributes or {}).get("enrichment", {}).get("reputation") == "malicious":
            raw += 15
        raw += int((e.anomaly_score or 0) * 10)

    for etype, n in sorted(by_type.items(), key=lambda x: -x[1]):
        factors.append(f"{n}× {etype}")

    # Squash to 0..100 (diminishing returns).
    score = round(100 * (1 - 1 / (1 + raw / 40.0)), 1)
    return {
        "entity_type": entity_type,
        "entity": value,
        "risk_score": score,
        "event_count": len(events),
        "factors": factors[:6],
        "window_days": days,
    }


def incident_risk_timeline(db: Session, incident: Incident) -> list[dict]:
    """Cumulative entity risk across the incident's events, in order — shows how
    risk escalated step by step."""
    events = (db.query(Event).filter(Event.incident_id == incident.id)
              .order_by(Event.timestamp).all())
    timeline: list[dict] = []
    cumulative = 0
    for e in events:
        cumulative += _EVENT_RISK.get(e.event_type, 1)
        if (e.attributes or {}).get("enrichment", {}).get("reputation") == "malicious":
            cumulative += 15
        score = round(100 * (1 - 1 / (1 + cumulative / 40.0)), 1)
        timeline.append({
            "timestamp": e.timestamp.isoformat(),
            "event_type": e.event_type,
            "entity": e.source_ip or e.username or "—",
            "cumulative_risk": score,
        })
    return timeline
