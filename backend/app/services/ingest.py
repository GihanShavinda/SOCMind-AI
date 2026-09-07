from sqlalchemy.orm import Session

from app.models import Event, Asset
from app.schemas import EventIn, IngestResult
from app.detection.engine import run_detection


def ingest_event(db: Session, payload: EventIn) -> IngestResult:
    """Normalise an incoming event into the unified schema, persist it, and run
    the detection engine. This is the single seam every collector talks to."""

    # Resolve asset by hostname (assets are pre-registered per the assumptions).
    asset = db.query(Asset).filter(Asset.hostname == payload.asset).first()

    event = Event(
        asset_id=asset.id if asset else None,
        timestamp=payload.timestamp,
        event_type=payload.event_type,
        source_ip=payload.source_ip,
        username=payload.username,
        severity=payload.severity,
        raw_ref=payload.raw_ref,
        attributes=payload.attributes,
    )
    db.add(event)
    db.flush()  # assign event.id before detection

    incident = run_detection(db, event)
    db.commit()

    return IngestResult(
        event_id=event.id,
        incident_id=incident.id if incident else None,
        detection=incident.title if incident else None,
    )
