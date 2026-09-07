from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Incident, Event, AuditLog, User
from app.schemas import IncidentOut, EventOut, AuditOut

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Incident).order_by(Incident.created_at.desc()).all()


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident


@router.get("/{incident_id}/events", response_model=list[EventOut])
def incident_events(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return (
        db.query(Event)
        .filter(Event.incident_id == incident_id)
        .order_by(Event.timestamp)
        .all()
    )


# Simple audit feed (append-only). Mounted here for convenience.
audit_router = APIRouter(prefix="/api/audit", tags=["audit"])


@audit_router.get("", response_model=list[AuditOut])
def list_audit(
    limit: int = 100, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
