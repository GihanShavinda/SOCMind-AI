from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Incident, User
from app.schemas import AssistantAnalysis, CommandRec
from app.ai import assistant, catalog

router = APIRouter(prefix="/api/incidents", tags=["ai"])


@router.get("/{incident_id}/analysis", response_model=AssistantAnalysis)
def incident_analysis(
    incident_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Grounded AI investigation analysis: what happened, why it is suspicious,
    and prioritised next steps with safe, approved commands (FR-21..29).

    Works without an LLM (deterministic, evidence-grounded fallback); if an LLM
    is configured it drafts the narrative, but commands always come from the
    approved catalog and are validated (safe by construction)."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    result = assistant.analyse(db, incident)
    return AssistantAnalysis(incident_id=incident_id, **result)


@router.get("/{incident_id}/commands", response_model=list[CommandRec])
def incident_commands(
    incident_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Just the approved, risk-classified commands recommended for this incident
    (FR-24..28), for clients that only want the action list."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    ctx = assistant.build_context(db, incident)
    cmds = catalog.recommend(ctx["os_name"], ctx["event_types"])
    from app.ai import safety
    return [
        CommandRec(
            id=c.id, os=c.os, command=c.command, purpose=c.purpose,
            why=c.why, risk=safety.classify(c.command, c.risk),
        )
        for c in cmds
    ]
