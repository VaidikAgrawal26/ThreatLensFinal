from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.db import get_db
from app.models import User, AuditLog
from app.schemas import RegisterRequest, LoginRequest, TokenResponse, UserOut
from app.core.security import create_access_token, get_current_user, hash_password, verify_password
router=APIRouter(prefix="/api/auth",tags=["Authentication"])
def audit(db,user,action,target=None,details=None):
    db.add(AuditLog(user_id=getattr(user,"id",None),actor_email=getattr(user,"email","system"),action=action,target=target,details=details or {}))
@router.post("/register",response_model=UserOut)
def register(payload:RegisterRequest,db:Session=Depends(get_db)):
    email=str(payload.email).lower().strip()
    if db.query(User).filter(User.email==email).first():
        raise HTTPException(409,"Email already registered")
    requested_role=payload.role
    if requested_role not in {"administrator","soc_member","security_analyst","researcher"}:
        raise HTTPException(422,"Choose one of the supported ThreatLens roles")
    # Public registration may request any role, but only Researcher accounts are activated
    # automatically. Privileged roles require an administrator to approve/activate them.
    active=requested_role=="researcher"
    user=User(email=email,password_hash=hash_password(payload.password),full_name=payload.full_name.strip(),role=requested_role,active=active)
    db.add(user)
    db.flush()
    audit(db,user,"auth.register",email,{"requested_role":requested_role,"active":active})
    db.commit()
    db.refresh(user)
    return user

@router.post("/login",response_model=TokenResponse)
def login(payload:LoginRequest,db:Session=Depends(get_db)):
    user=db.query(User).filter(User.email==str(payload.email).lower().strip()).first()
    if not user or not verify_password(payload.password,user.password_hash):
        raise HTTPException(401,"Incorrect email or password")
    if not user.active:
        raise HTTPException(403,"This account is pending administrator approval or has been deactivated.")
    if payload.role and payload.role != user.role:
        raise HTTPException(403,"The selected role does not match this account. Choose the role assigned to your account.")
    user.last_login_at=datetime.now(timezone.utc)
    audit(db,user,"auth.login",user.email,{"role":user.role})
    db.commit()
    db.refresh(user)
    return {"access_token":create_access_token(user),"token_type":"bearer","user":user}
@router.get("/me",response_model=UserOut)
def me(user:User=Depends(get_current_user)): return user
@router.post("/logout")
def logout(user:User=Depends(get_current_user),db:Session=Depends(get_db)):
    audit(db,user,"auth.logout",user.email); db.commit(); return {"message":"Logged out. Remove the bearer token from the client."}
