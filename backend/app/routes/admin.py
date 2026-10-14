from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db import get_db
from app.models import User, AuditLog, Scan
from app.schemas import AdminCreateUser, UserOut, RoleUpdate, StatusUpdate
from app.core.security import hash_password, require_roles
router=APIRouter(prefix="/api/admin",tags=["Administration"])
def record(db,actor,action,target,details=None): db.add(AuditLog(user_id=actor.id,actor_email=actor.email,action=action,target=str(target),details=details or {}))
@router.get("/users",response_model=list[UserOut])
def users(db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))): return db.query(User).order_by(User.id).all()
@router.post("/users",response_model=UserOut)
def create_user(payload:AdminCreateUser,db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    email=str(payload.email).lower().strip()
    if db.query(User).filter(User.email==email).first(): raise HTTPException(409,"Email already registered")
    u=User(email=email,password_hash=hash_password(payload.password),full_name=payload.full_name.strip(),role=payload.role,active=True); db.add(u); db.flush(); record(db,actor,"admin.user_created",u.id,{"role":u.role}); db.commit(); db.refresh(u); return u
@router.patch("/users/{user_id}/role",response_model=UserOut)
def role(user_id:int,payload:RoleUpdate,db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    u=db.get(User,user_id)
    if not u: raise HTTPException(404,"User not found")
    if u.id==actor.id and payload.role!="administrator": raise HTTPException(400,"Cannot remove your own administrator role")
    old=u.role; u.role=payload.role; record(db,actor,"admin.role_changed",u.id,{"from":old,"to":u.role}); db.commit(); db.refresh(u); return u
@router.patch("/users/{user_id}/status",response_model=UserOut)
def status(user_id:int,payload:StatusUpdate,db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    u=db.get(User,user_id)
    if not u: raise HTTPException(404,"User not found")
    if u.id==actor.id and not payload.active: raise HTTPException(400,"Cannot deactivate your own account")
    u.active=payload.active; record(db,actor,"admin.user_status_changed",u.id,{"active":u.active}); db.commit(); db.refresh(u); return u
@router.get("/audit")
def audit(db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    return [{"id":x.id,"user_id":x.user_id,"actor_email":x.actor_email,"action":x.action,"target":x.target,"details":x.details,"created_at":x.created_at} for x in db.query(AuditLog).order_by(desc(AuditLog.id)).limit(1000).all()]
@router.get("/overview")
def overview(db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    return {"users":db.query(User).count(),"active_users":db.query(User).filter(User.active.is_(True)).count(),"scans":db.query(Scan).count(),"audit_events":db.query(AuditLog).count()}
