from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Incident, Event, AttackStep, AuditLog, User
from app.schemas import (
    IncidentOut, EventOut, AttackStepOut, AuditOut, IncidentGraph, KillChainPhase,
)
from app.detection.graph import build_graph
from app.detection.mitre import build_kill_chain

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


@router.get("/{incident_id}/story", response_model=list[AttackStepOut])
def incident_story(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """Ordered attack-story narrative for an incident (FR-16)."""
    return (
        db.query(AttackStep)
        .filter(AttackStep.incident_id == incident_id)
        .order_by(AttackStep.order)
        .all()
    )


@router.get("/{incident_id}/graph", response_model=IncidentGraph)
def incident_graph(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """Interactive attack graph reconstructed from the incident's events (FR-17)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    events = (
        db.query(Event).filter(Event.incident_id == incident_id)
        .order_by(Event.timestamp).all()
    )
    return build_graph(incident, events)


@router.get("/{incident_id}/killchain", response_model=list[KillChainPhase])
def incident_killchain(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """Observed techniques positioned along the kill chain for this incident (FR-20)."""
    steps = (
        db.query(AttackStep).filter(AttackStep.incident_id == incident_id).all()
    )
    mitre_ids = [s.mitre_id for s in steps if s.mitre_id]
    return build_kill_chain(mitre_ids)


# Simple audit feed (append-only). Mounted here for convenience.
audit_router = APIRouter(prefix="/api/audit", tags=["audit"])


@audit_router.get("", response_model=list[AuditOut])
def list_audit(
    limit: int = 100, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
