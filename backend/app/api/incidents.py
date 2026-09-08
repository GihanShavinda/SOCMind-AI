from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_role
from app.models import Incident, Event, AttackStep, AuditLog, User, Feedback
from app.models.common import Role, IncidentStatus, FeedbackVerdict
from app.schemas import (
    IncidentOut, EventOut, AttackStepOut, AuditOut, IncidentGraph, KillChainPhase,
    AssistantAnalysis, SimilarIncident, FeedbackIn, FeedbackOut,
)
from app.detection.graph import build_graph
from app.detection.mitre import build_kill_chain
from app.detection.triage import is_breached
from app.ai import assistant as ai_assistant
from app.audit.logger import write_audit

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _to_out(incident: Incident) -> IncidentOut:
    o = IncidentOut.model_validate(incident)
    o.sla_breached = is_breached(incident)
    return o


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    sort: str = "triage",       # triage | recent
    db: Session = Depends(get_db), _: User = Depends(get_current_user),
):
    q = db.query(Incident)
    if sort == "triage":
        q = q.order_by(Incident.triage_score.desc(), Incident.created_at.desc())
    else:
        q = q.order_by(Incident.created_at.desc())
    return [_to_out(i) for i in q.all()]


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return _to_out(incident)


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


@router.get("/{incident_id}/assistant", response_model=AssistantAnalysis)
def incident_assistant(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """Grounded AI analysis: what happened, why suspicious, safe next steps
    (FR-21..29). Uses the deterministic engine unless an LLM is configured."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    result = ai_assistant.analyse(db, incident)
    return {"incident_id": incident_id, **result}


@router.get("/{incident_id}/similar", response_model=list[SimilarIncident])
def incident_similar(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """Similar past incidents from the local knowledge base (FR-23 / 8.2)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    from app.ai.rag import retrieve_similar
    return retrieve_similar(db, incident, top_k=5)


@router.get("/{incident_id}/feedback", response_model=list[FeedbackOut])
def list_feedback(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return (db.query(Feedback).filter(Feedback.incident_id == incident_id)
            .order_by(Feedback.created_at.desc()).all())


@router.post("/{incident_id}/feedback", response_model=FeedbackOut, status_code=201)
def add_feedback(
    incident_id: int, body: FeedbackIn, db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    """Record an analyst verdict (confirm/dismiss/correct). Feeds active learning
    (8.8) and updates the incident status accordingly."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    try:
        verdict = FeedbackVerdict(body.verdict)
    except ValueError:
        raise HTTPException(400, "verdict must be confirm, dismiss or correct")

    from app.detection.learning import primary_rule_for_incident
    fb = Feedback(
        incident_id=incident_id, analyst=user.email, verdict=verdict,
        rule_id=primary_rule_for_incident(db, incident_id), note=body.note,
    )
    db.add(fb)

    # Reflect the verdict in the incident's status.
    if verdict == FeedbackVerdict.DISMISS:
        incident.status = IncidentStatus.DISMISSED
    elif verdict == FeedbackVerdict.CONFIRM:
        incident.status = IncidentStatus.INVESTIGATING

    write_audit(db, actor=user.email, action=f"feedback.{verdict.value}",
                target=f"incident:{incident_id}", after=body.note)
    db.commit(); db.refresh(fb)
    return fb


# Simple audit feed (append-only). Mounted here for convenience.
audit_router = APIRouter(prefix="/api/audit", tags=["audit"])


@audit_router.get("", response_model=list[AuditOut])
def list_audit(
    limit: int = 100, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
