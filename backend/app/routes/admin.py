from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.security import hash_password, require_roles
from app.db import get_db
from app.models import AuditLog, Scan, User
from app.schemas import AdminCreateUser, RoleUpdate, StatusUpdate, UserOut

router = APIRouter(prefix="/api/admin", tags=["Administration"])


def record(db: Session, actor: User, action: str, target: object, details: dict | None = None):
    db.add(AuditLog(user_id=actor.id, actor_email=actor.email, action=action,
                    target=str(target), details=details or {}))


@router.get("/users", response_model=list[UserOut])
def users(limit: int = Query(default=500, ge=1, le=2000), offset: int = Query(default=0, ge=0),
          db: Session = Depends(get_db), actor: User = Depends(require_roles("administrator"))):
    return db.query(User).order_by(User.id).offset(offset).limit(limit).all()


@router.post("/users", response_model=UserOut)
def create_user(payload: AdminCreateUser, db: Session = Depends(get_db), actor: User = Depends(require_roles("administrator"))):
    email = str(payload.email).lower().strip()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Email already registered")
    user = User(email=email, password_hash=hash_password(payload.password), full_name=payload.full_name.strip(),
                role=payload.role, active=True)
    try:
        db.add(user)
        db.flush()
        record(db, actor, "admin.user_created", user.id, {"role": user.role})
        db.commit()
        db.refresh(user)
        return user
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "Email already registered") from exc


@router.patch("/users/{user_id}/role", response_model=UserOut)
def role(user_id: int, payload: RoleUpdate, db: Session = Depends(get_db), actor: User = Depends(require_roles("administrator"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == actor.id and payload.role != "administrator":
        raise HTTPException(400, "Cannot remove your own administrator role")
    if user.active and user.role == "administrator" and payload.role != "administrator":
        active_admins = db.query(User).filter(User.active.is_(True), User.role == "administrator").count()
        if active_admins <= 1:
            raise HTTPException(409, "The last active administrator cannot be demoted")
    old = user.role
    user.role = payload.role
    record(db, actor, "admin.role_changed", user.id, {"from": old, "to": user.role})
    db.commit()
    db.refresh(user)
    return user


@router.patch("/users/{user_id}/status", response_model=UserOut)
def status(user_id: int, payload: StatusUpdate, db: Session = Depends(get_db), actor: User = Depends(require_roles("administrator"))):
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    if user.id == actor.id and not payload.active:
        raise HTTPException(400, "Cannot deactivate your own account")
    if user.active and user.role == "administrator" and not payload.active:
        active_admins = db.query(User).filter(User.active.is_(True), User.role == "administrator").count()
        if active_admins <= 1:
            raise HTTPException(409, "The last active administrator cannot be deactivated")
    user.active = payload.active
    record(db, actor, "admin.user_status_changed", user.id, {"active": user.active})
    db.commit()
    db.refresh(user)
    return user


@router.get("/audit")
def audit(limit: int = Query(default=500, ge=1, le=2000), offset: int = Query(default=0, ge=0),
          action: str | None = Query(default=None, max_length=120),
          actor_email: str | None = Query(default=None, max_length=255),
          db: Session = Depends(get_db), actor: User = Depends(require_roles("administrator"))):
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action == action.strip())
    if actor_email:
        query = query.filter(AuditLog.actor_email.ilike(f"%{actor_email.strip()}%"))
    return [{"id": item.id, "user_id": item.user_id, "actor_email": item.actor_email,
             "action": item.action, "target": item.target, "details": item.details,
             "created_at": item.created_at}
            for item in query.order_by(desc(AuditLog.id)).offset(offset).limit(limit).all()]


@router.get("/overview")
def overview(db: Session = Depends(get_db), actor: User = Depends(require_roles("administrator"))):
    return {"users": db.query(User).count(), "active_users": db.query(User).filter(User.active.is_(True)).count(),
            "scans": db.query(Scan).count(), "audit_events": db.query(AuditLog).count()}
