from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from sqlalchemy.exc import IntegrityError
from app.db import get_db
from app.models import Incident, Scan, User, AuditLog
from app.schemas import IncidentCreate, IncidentUpdate
from app.core.security import require_roles
router=APIRouter(prefix="/api/incidents",tags=["Incident Management"])
ALLOWED={"administrator","soc_member","security_analyst"}
def serialize(i): return {"id":i.id,"scan_id":i.scan_id,"title":i.title,"status":i.status,"severity":i.severity,"assigned_to":i.assigned_to,"created_by":i.created_by,"notes":i.notes,"created_at":i.created_at,"updated_at":i.updated_at}
def audit(db,user,action,target,details=None): db.add(AuditLog(user_id=user.id,actor_email=user.email,action=action,target=str(target),details=details or {}))
@router.get("/assignees")
def assignees(db:Session=Depends(get_db),user:User=Depends(require_roles(*ALLOWED))):
    users=db.query(User).filter(User.active.is_(True),User.role.in_(list(ALLOWED))).order_by(User.full_name).all()
    return [{"id":u.id,"full_name":u.full_name,"email":u.email,"role":u.role} for u in users]
@router.get("")
def list_incidents(limit:int=Query(default=200,ge=1,le=1000),offset:int=Query(default=0,ge=0),db:Session=Depends(get_db),user:User=Depends(require_roles(*ALLOWED))):
    return [serialize(i) for i in db.query(Incident).order_by(desc(Incident.updated_at)).offset(offset).limit(limit).all()]
@router.post("")
def create_incident(payload:IncidentCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(*ALLOWED))):
    scan=db.get(Scan,payload.scan_id)
    if not scan: raise HTTPException(404,"Scan not found")
    existing=db.query(Incident).filter(Incident.scan_id==scan.id).first()
    if existing: raise HTTPException(409,"An incident already exists for this scan")
    item=Incident(scan_id=scan.id,title=payload.title.strip(),severity=scan.severity,status="open",created_by=user.id,notes=payload.notes.strip())
    try:
        db.add(item);db.flush();audit(db,user,"incident.created",item.id,{"scan_id":scan.id});db.commit();db.refresh(item);return serialize(item)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409,"An incident already exists for this scan") from exc
@router.patch("/{incident_id}")
def update_incident(incident_id:int,payload:IncidentUpdate,db:Session=Depends(get_db),user:User=Depends(require_roles(*ALLOWED))):
    item=db.get(Incident,incident_id)
    if not item: raise HTTPException(404,"Incident not found")
    changes={}
    if payload.status is not None:
        if payload.status != item.status:
            changes["status"]={"from":item.status,"to":payload.status}
            item.status=payload.status
    if "assigned_to" in payload.model_fields_set:
        if payload.assigned_to is None:
            changes["assigned_to"]={"from":item.assigned_to,"to":None};item.assigned_to=None
        else:
            assignee=db.get(User,payload.assigned_to)
            if not assignee or not assignee.active or assignee.role not in ALLOWED: raise HTTPException(400,"Assigned user must be an active SOC/analyst/administrator account")
            changes["assigned_to"]={"from":item.assigned_to,"to":assignee.id};item.assigned_to=assignee.id
    if payload.notes is not None and payload.notes != item.notes:
        item.notes=payload.notes
        changes["notes_updated"]=True
    if not changes:
        return serialize(item)
    audit(db,user,"incident.updated",item.id,changes);db.commit();db.refresh(item);return serialize(item)
