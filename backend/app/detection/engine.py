"""Layer 1 (rule) + Layer 3 (correlation) for the SSH brute-force slice.

This is deliberately deterministic and LLM-free: the platform must work with the
AI switched off (see the reliability NFR). Later phases add anomaly detection and
the grounded AI assistant on top of this spine.
"""
from datetime import timedelta

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Event, Alert, Incident
from app.models.common import Severity, IncidentStatus, utcnow
from app.audit.logger import write_audit


RULE_ID = "ssh_bruteforce_repeated_failures"


def run_detection(db: Session, event: Event) -> Incident | None:
    """Called after each event is ingested. Returns an Incident if one was
    created or updated, else None."""
    if event.event_type != "authentication_failure":
        return None

    window_start = event.timestamp - timedelta(
        seconds=settings.BRUTEFORCE_WINDOW_SECONDS
    )

    # Correlation keys: same asset + same source IP within the time window.
    related = (
        db.query(Event)
        .filter(
            and_(
                Event.event_type == "authentication_failure",
                Event.asset_id == event.asset_id,
                Event.source_ip == event.source_ip,
                Event.timestamp >= window_start,
                Event.timestamp <= event.timestamp,
            )
        )
        .all()
    )

    if len(related) < settings.BRUTEFORCE_FAILED_THRESHOLD:
        return None

    # Is there already an open incident for this asset+IP? De-duplicate.
    existing = next(
        (e.incident for e in related if e.incident is not None), None
    )

    confidence = min(0.99, 0.5 + 0.05 * len(related))

    if existing is None:
        incident = Incident(
            title=f"SSH brute force from {event.source_ip}",
            confidence=confidence,
            severity=Severity.HIGH,
            status=IncidentStatus.OPEN,
            related_count=len(related),
            asset_id=event.asset_id,
        )
        db.add(incident)
        db.flush()
        write_audit(
            db,
            actor="system",
            action="incident.created",
            target=f"incident:{incident.id}",
            after=f"{len(related)} failed logins from {event.source_ip}",
        )
    else:
        incident = existing
        incident.related_count = len(related)
        incident.confidence = confidence

    # Attach the correlated events + raise an alert for this event.
    for e in related:
        e.incident_id = incident.id

    db.add(
        Alert(
            event_id=event.id,
            rule_id=RULE_ID,
            layer="correlation",
            score=confidence,
            created_at=utcnow(),
            incident_id=incident.id,
        )
    )
    db.flush()
    return incident
