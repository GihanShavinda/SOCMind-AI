from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

import hashlib
import secrets
from datetime import timedelta

from app.core.database import get_db
from app.core.config import settings
from app.core.deps import get_current_user
from app.core.security import (
    verify_password, hash_password, create_access_token, create_refresh_token, decode_token,
)
from app.core import totp
from app.core.email import send_reset_link
from app.models import User, PasswordResetToken
from app.models.common import utcnow
from app.schemas import (
    TokenPair, RefreshRequest, UserOut, MfaSetupOut, MfaCodeIn,
    ForgotPasswordIn, ForgotPasswordOut, ResetPasswordIn, ChangePasswordIn,
    ProfileUpdateIn,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=TokenPair)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    otp: str | None = Form(default=None),
    db: Session = Depends(get_db),
):
    """OAuth2 password flow. 'username' carries the email. If the account has MFA
    enabled, a valid 'otp' (TOTP code) must also be supplied (FR-2)."""
    user = db.query(User).filter(User.email == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if user.mfa_enabled:
        if not otp:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="MFA code required")
        if not (user.mfa_secret and totp.verify(user.mfa_secret, otp)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid MFA code")
    return TokenPair(
        access_token=create_access_token(user.email, user.role.value),
        refresh_token=create_refresh_token(user.email, user.role.value),
    )


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = db.query(User).filter(User.email == payload.get("sub")).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found")
    return TokenPair(
        access_token=create_access_token(user.email, user.role.value),
        refresh_token=create_refresh_token(user.email, user.role.value),
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


# ---- MFA management (FR-2) ----
@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate a new TOTP secret. The user scans/pastes the URI into their
    authenticator, then confirms with /mfa/enable. Not enabled until confirmed."""
    secret = totp.generate_secret()
    user.mfa_secret = secret
    db.commit()
    return MfaSetupOut(secret=secret,
                       otpauth_uri=totp.provisioning_uri(secret, user.email))


@router.post("/mfa/enable", response_model=UserOut)
def mfa_enable(body: MfaCodeIn, user: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    if not user.mfa_secret:
        raise HTTPException(400, "Run /mfa/setup first")
    if not totp.verify(user.mfa_secret, body.code):
        raise HTTPException(400, "Invalid code")
    user.mfa_enabled = True
    db.commit(); db.refresh(user)
    return user


@router.post("/mfa/disable", response_model=UserOut)
def mfa_disable(body: MfaCodeIn, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    if user.mfa_enabled and not (user.mfa_secret and totp.verify(user.mfa_secret, body.code)):
        raise HTTPException(400, "Invalid code")
    user.mfa_enabled = False
    user.mfa_secret = None
    db.commit(); db.refresh(user)
    return user


# ---- Password reset (FR-1) ----
def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


@router.post("/forgot-password", response_model=ForgotPasswordOut)
def forgot_password(body: ForgotPasswordIn, db: Session = Depends(get_db)):
    """Request a reset link. Always returns success (anti-enumeration): the
    response never reveals whether the email is registered."""
    user = db.query(User).filter(User.email == body.email).first()
    dev_link = None
    if user:
        raw = secrets.token_urlsafe(32)
        db.add(PasswordResetToken(
            user_id=user.id, token_hash=_hash_token(raw),
            expires_at=utcnow() + timedelta(minutes=settings.RESET_TOKEN_EXPIRE_MINUTES),
        ))
        db.commit()
        link = f"{settings.APP_BASE_URL}/reset-password?token={raw}"
        send_reset_link(user.email, link)
        if settings.EMAIL_MODE != "smtp":
            dev_link = link       # surface the link in dev/lab mode only
    return ForgotPasswordOut(
        message="If that account exists, a reset link has been sent.",
        dev_reset_link=dev_link,
    )


@router.post("/reset-password", response_model=UserOut)
def reset_password(body: ResetPasswordIn, db: Session = Depends(get_db)):
    row = (db.query(PasswordResetToken)
           .filter(PasswordResetToken.token_hash == _hash_token(body.token))
           .first())
    expires = row.expires_at if row else None
    if expires and expires.tzinfo is None:
        from datetime import timezone
        expires = expires.replace(tzinfo=timezone.utc)   # SQLite returns naive
    if not row or row.used or (expires and expires < utcnow()):
        raise HTTPException(400, "Invalid or expired reset token")
    if len(body.new_password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    user = db.get(User, row.user_id)
    user.password_hash = hash_password(body.new_password)
    row.used = True
    db.commit(); db.refresh(user)
    return user


# ---- Self-service profile (FR-1) ----
@router.patch("/me", response_model=UserOut)
def update_profile(body: ProfileUpdateIn, user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    user.name = body.name
    db.commit(); db.refresh(user)
    return user


@router.post("/change-password", response_model=UserOut)
def change_password(body: ChangePasswordIn, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    user.password_hash = hash_password(body.new_password)
    db.commit(); db.refresh(user)
    return user
