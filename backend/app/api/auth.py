from fastapi import APIRouter, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import (
    verify_password, create_access_token, create_refresh_token, decode_token,
)
from app.core import totp
from app.models import User
from app.schemas import (
    TokenPair, RefreshRequest, UserOut, MfaSetupOut, MfaCodeIn,
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
