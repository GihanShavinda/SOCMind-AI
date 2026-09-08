from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_role
from app.models import Incident, User
from app.models.common import Role
from app.ueba.scoring import entity_risk, incident_risk_timeline
from app.hunting.engine import run_hunt, hunt_to_sigma
from app.forensics.custody import case_package
from app.ai.model_cards import model_cards, calibration_report


# ---- request models ----
class HuntFilter(BaseModel):
    field: str
    op: str = "eq"
    value: str


class HuntRequest(BaseModel):
    filters: list[HuntFilter] = []
    hours: int = 168


class PromoteRequest(BaseModel):
    name: str
    filters: list[HuntFilter] = []
    count: int = 5
    window_seconds: int = 120


router = APIRouter(prefix="/api", tags=["advanced"])


# ---- UEBA (8.3) ----
@router.get("/ueba/entity")
def ueba_entity(entity_type: str, value: str, db: Session = Depends(get_db),
                _: User = Depends(get_current_user)):
    if entity_type not in ("user", "ip", "host"):
        raise HTTPException(400, "entity_type must be user, ip or host")
    return entity_risk(db, entity_type, value)


@router.get("/incidents/{incident_id}/risk-timeline")
def risk_timeline(incident_id: int, db: Session = Depends(get_db),
                  _: User = Depends(get_current_user)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return incident_risk_timeline(db, incident)


# ---- Threat hunting (8.4) ----
@router.post("/hunt")
def hunt(body: HuntRequest, db: Session = Depends(get_db),
         _: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST))):
    return run_hunt(db, [f.model_dump() for f in body.filters], hours=body.hours)


@router.post("/hunt/promote")
def promote(body: PromoteRequest,
            _: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST))):
    """Promote a saved hunt into a Sigma-style detection rule (returns YAML)."""
    yaml_text = hunt_to_sigma(body.name, [f.model_dump() for f in body.filters],
                              count=body.count, window_seconds=body.window_seconds)
    return {"rule_yaml": yaml_text,
            "note": "Save this to detection-rules/ and restart to activate."}


# ---- Forensics & chain of custody (8.6) ----
@router.get("/incidents/{incident_id}/case-package")
def case_pkg(incident_id: int, db: Session = Depends(get_db),
             _: User = Depends(get_current_user)):
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return case_package(db, incident)


# ---- Model cards & calibration (8.10) ----
@router.get("/model-cards")
def get_model_cards(_: User = Depends(get_current_user)):
    return model_cards()


@router.get("/calibration")
def get_calibration(db: Session = Depends(get_db),
                    _: User = Depends(get_current_user)):
    return calibration_report(db)
