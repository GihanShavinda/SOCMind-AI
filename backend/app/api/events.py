from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Event, User
from app.schemas import EventIn, EventOut, IngestResult
from app.services.ingest import ingest_event

router = APIRouter(prefix="/api/events", tags=["events"])


@router.post("/ingest", response_model=IngestResult)
def ingest(payload: EventIn, db: Session = Depends(get_db)):
    """Collectors POST normalised events here. Left unauthenticated for the lab;
    in production put this behind a collector API key or mTLS."""
    return ingest_event(db, payload)


@router.get("", response_model=list[EventOut])
def list_events(
    limit: int = 100,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return (
        db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()
    )
