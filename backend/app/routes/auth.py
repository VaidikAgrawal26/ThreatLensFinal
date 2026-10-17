from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import (
    DUMMY_PASSWORD_HASH, bearer, create_access_token, get_current_user, hash_password,
    revoke_current_token, verify_password,
)
from app.db import get_db
from app.models import AuditLog, LoginAttempt, User
from app.schemas import LoginRequest, ProfileUpdate, RegisterRequest, TokenResponse, UserOut

router = APIRouter(prefix="/api/auth", tags=["Authentication"])
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_ATTEMPT_LIMIT = 8


def audit(db: Session, user: User | None, action: str, target: str | None = None, details: dict | None = None):
    db.add(AuditLog(
        user_id=getattr(user, "id", None), actor_email=getattr(user, "email", target or "system"),
        action=action, target=target, details=details or {},
    ))


@router.post("/register", response_model=UserOut)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    full_name = payload.full_name.strip()
    if len(full_name) < 2:
        raise HTTPException(422, "Full name must contain at least two non-space characters")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Email already registered")

    # Only the least-privileged Researcher role activates through public registration.
    active = payload.role == "researcher"
    user = User(email=email, password_hash=hash_password(payload.password), full_name=full_name,
                role=payload.role, active=active)
    try:
        db.add(user)
        db.flush()
        audit(db, user, "auth.register", email, {"requested_role": user.role, "active": active})
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Email already registered") from exc


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    now = datetime.now(timezone.utc)
    window_start = now - LOGIN_WINDOW
    db.query(LoginAttempt).filter(LoginAttempt.attempted_at < now - timedelta(days=2)).delete(synchronize_session=False)
    failures = db.query(LoginAttempt).filter(
        LoginAttempt.email == email, LoginAttempt.attempted_at >= window_start,
    ).count()
    if failures >= LOGIN_ATTEMPT_LIMIT:
        audit(db, None, "auth.login_throttled", email, {"window_minutes": 15, "attempt_count": failures})
        db.commit()
        raise HTTPException(429, "Too many failed sign-in attempts. Wait before trying again.", headers={"Retry-After": "900"})

    user = db.query(User).filter(User.email == email).first()
    valid_password = verify_password(payload.password, user.password_hash if user else DUMMY_PASSWORD_HASH)
    if not user or not valid_password:
        db.add(LoginAttempt(email=email))
        audit(db, user, "auth.login_failed", email)
        db.commit()
        raise HTTPException(401, "Incorrect email or password")
    if not user.active:
        db.rollback()
        raise HTTPException(403, "This account is pending administrator approval or has been deactivated.")

    db.query(LoginAttempt).filter(LoginAttempt.email == email).delete(synchronize_session=False)
    if payload.role and payload.role != user.role:
        audit(db, user, "auth.login_role_mismatch", email, {"account_role": user.role})
        db.commit()
        raise HTTPException(403, "The selected role does not match this account. Choose the role assigned to your account.")

    user.last_login_at = now
    audit(db, user, "auth.login", user.email, {"role": user.role})
    db.commit()
    db.refresh(user)
    return {"access_token": create_access_token(user), "token_type": "bearer", "user": user}


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.patch("/profile", response_model=UserOut)
def update_profile(payload: ProfileUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if payload.email is None and payload.full_name is None:
        raise HTTPException(422, "Provide an email or display name to update")
    if payload.email is not None:
        email = str(payload.email).lower().strip()
        existing = db.query(User).filter(User.email == email, User.id != user.id).first()
        if existing:
            raise HTTPException(409, "Email already registered")
        user.email = email
    if payload.full_name is not None:
        full_name = payload.full_name.strip()
        if len(full_name) < 2:
            raise HTTPException(422, "Full name must contain at least two non-space characters")
        user.full_name = full_name
    audit(db, user, "auth.profile_updated", user.email,
          {"updated_email": payload.email is not None, "updated_full_name": payload.full_name is not None})
    try:
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Email already registered") from exc


@router.post("/logout")
def logout(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
):
    revoke_current_token(credentials, db)
    audit(db, user, "auth.logout", user.email)
    db.commit()
    return {"message": "Session revoked. Remove the bearer token from the client."}
