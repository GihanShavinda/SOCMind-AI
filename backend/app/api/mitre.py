from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import AttackStep, User
from app.schemas import KillChainPhase
from app.detection.mitre import build_kill_chain

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("/killchain", response_model=list[KillChainPhase])
def killchain_matrix(
    db: Session = Depends(get_db), _: User = Depends(get_current_user)
):
    """Kill chain aggregated across every incident — the standardised lifecycle
    view showing which techniques have been observed platform-wide (FR-20)."""
    mitre_ids = [
        s.mitre_id for s in db.query(AttackStep).all() if s.mitre_id
    ]
    return build_kill_chain(mitre_ids)
