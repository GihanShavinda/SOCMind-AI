from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import require_role, get_current_user
from app.core.security import hash_password
from app.models import User
from app.models.common import Role
from app.schemas import UserOut, AdminUserCreate, AdminUserUpdate
from app.audit.logger import write_audit

router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(db: Session = Depends(get_db),
               _: User = Depends(require_role(Role.ADMINISTRATOR))):
    return db.query(User).order_by(User.id).all()


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: AdminUserCreate, db: Session = Depends(get_db),
                admin: User = Depends(require_role(Role.ADMINISTRATOR))):
    if db.query(User).filter(User.email == body.email).first():
        raise HTTPException(400, "Email already registered")
    user = User(name=body.name, email=body.email,
                password_hash=hash_password(body.password), role=body.role)
    db.add(user); db.flush()
    write_audit(db, actor=admin.email, action="user.created", target=f"user:{user.id}")
    db.commit(); db.refresh(user)
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, body: AdminUserUpdate, db: Session = Depends(get_db),
                admin: User = Depends(require_role(Role.ADMINISTRATOR))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active
    write_audit(db, actor=admin.email, action="user.updated", target=f"user:{user.id}")
    db.commit(); db.refresh(user)
    return user
