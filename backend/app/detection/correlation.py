"""Correlation + incident assembly for the layered detection engine (Phase 2).

Threshold evaluation is done in Python after a coarse DB query so it stays
database-agnostic (works on both Postgres and the SQLite test DB) and can count
distinct attribute values (e.g. distinct dest_port for a port scan).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import Event, Alert, Incident, AttackStep
from app.models.common import Severity, IncidentStatus, utcnow
from app.detection.mitre import technique_name
from app.detection.rules.loader import Rule
from app.audit.logger import write_audit

_SEV = {
    "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}
_SEV_RANK = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}


def _group_key(event: Event, keys: list[str]) -> tuple:
    vals = []
    for k in keys:
        vals.append(getattr(event, k, None) if hasattr(event, k)
                    else (event.attributes or {}).get(k))
    return tuple(vals)


def evaluate_threshold(db: Session, event: Event, rule: Rule) -> list[Event] | None:
    """Return the correlated events if the rule's threshold is met, else None."""
    corr = rule.correlation
    window_start = event.timestamp - timedelta(seconds=corr.window_seconds)

    # Coarse query: same event_type within the window. Refine in Python.
    candidates = (
        db.query(Event)
        .filter(
            Event.event_type == rule.event_type,
            Event.timestamp >= window_start,
            Event.timestamp <= event.timestamp,
        )
        .all()
    )

    target_key = _group_key(event, corr.group_by)
    grouped = [e for e in candidates
               if _group_key(e, corr.group_by) == target_key and rule.matches(e)]

    if corr.distinct_field:
        distinct = {(e.attributes or {}).get(corr.distinct_field) for e in grouped}
        distinct.discard(None)
        met = len(distinct) >= corr.count
    else:
        met = len(grouped) >= corr.count

    return grouped if met else None


def add_step(db: Session, incident: Incident, description: str,
             mitre_id: str | None = None, ts=None) -> None:
    order = len(incident.steps) + 1
    db.add(AttackStep(
        incident_id=incident.id, order=order, timestamp=ts,
        description=description, mitre_id=mitre_id,
        mitre_name=technique_name(mitre_id),
    ))


def open_incident_for(events: list[Event]) -> Incident | None:
    for e in events:
        if e.incident is not None:
            return e.incident
    return None


def create_or_update_incident(
    db: Session, event: Event, rule: Rule, correlated: list[Event],
) -> Incident:
    """Create a new incident for a threshold hit, or update the existing one."""
    confidence = min(0.99, 0.5 + 0.05 * len(correlated))
    incident = open_incident_for(correlated)

    if incident is None:
        incident = Incident(
            title=rule.incident_title.format(
                source_ip=event.source_ip, asset=_asset_name(event),
                event_type=event.event_type,
            ),
            confidence=confidence,
            severity=_SEV.get(rule.severity, Severity.MEDIUM),
            status=IncidentStatus.OPEN,
            related_count=len(correlated),
            asset_id=event.asset_id,
        )
        db.add(incident)
        db.flush()
        add_step(db, incident,
                 f"Detected {rule.title.lower()} ({len(correlated)} events).",
                 mitre_id=rule.mitre, ts=event.timestamp)
        write_audit(db, actor="system", action="incident.created",
                    target=f"incident:{incident.id}",
                    after=f"{rule.id}: {len(correlated)} events")
    else:
        incident.related_count = len(correlated)
        incident.confidence = max(incident.confidence, confidence)

    for e in correlated:
        e.incident_id = incident.id

    db.add(Alert(event_id=event.id, rule_id=rule.id, layer="correlation",
                 score=confidence, created_at=utcnow(), incident_id=incident.id))
    db.flush()
    return incident


def create_single_incident(db: Session, event: Event, rule: Rule) -> Incident:
    incident = Incident(
        title=rule.incident_title.format(
            source_ip=event.source_ip, asset=_asset_name(event),
            event_type=event.event_type,
        ),
        confidence=0.7,
        severity=_SEV.get(rule.severity, Severity.MEDIUM),
        status=IncidentStatus.OPEN,
        related_count=1,
        asset_id=event.asset_id,
    )
    db.add(incident)
    db.flush()
    event.incident_id = incident.id
    add_step(db, incident, f"Detected {rule.title.lower()}.",
             mitre_id=rule.mitre, ts=event.timestamp)
    db.add(Alert(event_id=event.id, rule_id=rule.id, layer="rule",
                 score=0.7, created_at=utcnow(), incident_id=incident.id))
    write_audit(db, actor="system", action="incident.created",
                target=f"incident:{incident.id}", after=rule.id)
    db.flush()
    return incident


def escalate(db: Session, incident: Incident, event: Event,
             failures: int) -> None:
    """Raise severity/confidence when a success follows brute-force failures."""
    incident.severity = Severity.CRITICAL
    incident.confidence = min(0.99, incident.confidence + 0.1)
    incident.title = f"Successful compromise after brute force from {event.source_ip}"
    event.incident_id = incident.id
    add_step(db, incident,
             f"Successful login for '{event.username}' from {event.source_ip} "
             f"after {failures} failed attempts — likely compromise.",
             mitre_id="T1078", ts=event.timestamp)
    db.add(Alert(event_id=event.id, rule_id="bruteforce_success_escalation",
                 layer="correlation", score=0.95, created_at=utcnow(),
                 incident_id=incident.id))
    write_audit(db, actor="system", action="incident.escalated",
                target=f"incident:{incident.id}",
                before="high", after="critical")
    db.flush()


def raise_severity_if_lower(incident: Incident, sev: Severity) -> None:
    if _SEV_RANK[sev] > _SEV_RANK[incident.severity]:
        incident.severity = sev


def _asset_name(event: Event) -> str:
    return event.asset.hostname if event.asset else "unknown asset"
