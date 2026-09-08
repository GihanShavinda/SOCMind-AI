from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_role
from app.models import Incident, Action, Decision, AttackStep, Event, User
from app.models.common import Role, ActionStatus, RiskLevel
from app.schemas import (
    PlaybookOut, DecisionOut, ActionOut, ProposeActionIn,
)
from app.response import playbooks as pb_engine
from app.response import actions as action_service

# --- Per-incident response endpoints ---
router = APIRouter(prefix="/api/incidents", tags=["response"])


@router.get("/{incident_id}/playbook", response_model=PlaybookOut | None)
def incident_playbook(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """The best-matching response playbook for this incident (FR-30, FR-31)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    steps = db.query(AttackStep).filter(AttackStep.incident_id == incident_id).all()
    events = db.query(Event).filter(Event.incident_id == incident_id).all()
    pb = pb_engine.select_for_incident(steps, events)
    return pb  # Pydantic reads the dataclass fields


@router.get("/{incident_id}/decisions", response_model=list[DecisionOut])
def incident_decisions(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return (
        db.query(Decision).filter(Decision.incident_id == incident_id)
        .order_by(Decision.created_at.desc()).all()
    )


@router.get("/{incident_id}/actions", response_model=list[ActionOut])
def incident_actions(
    incident_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return (
        db.query(Action).filter(Action.incident_id == incident_id)
        .order_by(Action.created_at.desc()).all()
    )


@router.post("/{incident_id}/actions", response_model=ActionOut)
def propose_action(
    incident_id: int,
    body: ProposeActionIn,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    """Propose a response action. The decision engine decides automate vs approval
    (FR-32, FR-33); low-risk auto-approved actions execute immediately (simulated)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    action = action_service.propose_action(db, incident, body.action_type, user.email)
    db.commit()
    db.refresh(action)
    return action


# --- Approval queue + lifecycle ---
actions_router = APIRouter(prefix="/api/actions", tags=["response"])


@actions_router.get("", response_model=list[ActionOut])
def list_actions(
    status: str | None = None,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = db.query(Action)
    if status:
        q = q.filter(Action.status == ActionStatus(status))
    return q.order_by(Action.created_at.desc()).all()


def _get(db: Session, action_id: int) -> Action:
    a = db.get(Action, action_id)
    if not a:
        raise HTTPException(404, "Action not found")
    return a


@actions_router.post("/{action_id}/approve", response_model=ActionOut)
def approve(
    action_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    a = _get(db, action_id)
    # FR-3: High/Restricted responses require an Administrator to approve.
    if a.risk_level in (RiskLevel.HIGH, RiskLevel.RESTRICTED) and user.role != Role.ADMINISTRATOR:
        raise HTTPException(
            403, "High/Restricted actions require an Administrator to approve"
        )
    try:
        a = action_service.approve_action(db, a, user.email)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.commit(); db.refresh(a); return a


@actions_router.post("/{action_id}/reject", response_model=ActionOut)
def reject(
    action_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    try:
        a = action_service.reject_action(db, _get(db, action_id), user.email)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.commit(); db.refresh(a); return a


@actions_router.post("/{action_id}/rollback", response_model=ActionOut)
def rollback(
    action_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    try:
        a = action_service.rollback_action(db, _get(db, action_id), user.email)
    except ValueError as e:
        raise HTTPException(400, str(e))
    db.commit(); db.refresh(a); return a


# --- Decision panel feed (FR-37): recent decisions with rationale ---
decisions_router = APIRouter(prefix="/api/decisions", tags=["response"])


@decisions_router.get("", response_model=list[DecisionOut])
def recent_decisions(
    limit: int = 50, db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    return db.query(Decision).order_by(Decision.created_at.desc()).limit(limit).all()
