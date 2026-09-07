from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user, require_role
from app.models import Asset, User
from app.models.common import Role
from app.schemas import AssetCreate, AssetUpdate, AssetOut
from app.audit.logger import write_audit

router = APIRouter(prefix="/api/assets", tags=["assets"])


@router.get("", response_model=list[AssetOut])
def list_assets(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    return db.query(Asset).order_by(Asset.id).all()


@router.post("", response_model=AssetOut, status_code=201)
def create_asset(
    body: AssetCreate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    asset = Asset(**body.model_dump())
    db.add(asset)
    db.flush()
    write_audit(db, actor=user.email, action="asset.created", target=f"asset:{asset.id}")
    db.commit()
    db.refresh(asset)
    return asset


@router.patch("/{asset_id}", response_model=AssetOut)
def update_asset(
    asset_id: int,
    body: AssetUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR, Role.ANALYST)),
):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(asset, k, v)
    write_audit(db, actor=user.email, action="asset.updated", target=f"asset:{asset.id}")
    db.commit()
    db.refresh(asset)
    return asset


@router.delete("/{asset_id}", status_code=204)
def retire_asset(
    asset_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(require_role(Role.ADMINISTRATOR)),
):
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    db.delete(asset)
    write_audit(db, actor=user.email, action="asset.retired", target=f"asset:{asset_id}")
    db.commit()
