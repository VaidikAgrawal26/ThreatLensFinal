from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db import get_db
from app.models import ResearchAnnotation, ExperimentNote, Scan, User, AuditLog
from app.schemas import AnnotationCreate, ExperimentNoteCreate
from app.core.security import require_roles
router=APIRouter(prefix="/api/research",tags=["Research Workspace"])
ROLES=("administrator","security_analyst","researcher")
def audit(db,user,action,target,details=None): db.add(AuditLog(user_id=user.id,actor_email=user.email,action=action,target=str(target),details=details or {}))
def ann(a): return {"id":a.id,"scan_id":a.scan_id,"ground_truth":a.ground_truth,"family":a.family,"dataset_source":a.dataset_source,"notes":a.notes,"created_by":a.created_by,"created_at":a.created_at,"updated_at":a.updated_at}
@router.get("/annotations")
def annotations(limit:int=Query(default=500,ge=1,le=2000),offset:int=Query(default=0,ge=0),db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    return [ann(a) for a in db.query(ResearchAnnotation).order_by(desc(ResearchAnnotation.updated_at)).offset(offset).limit(limit).all()]
@router.post("/annotations")
def upsert_annotation(payload:AnnotationCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    if not db.get(Scan,payload.scan_id): raise HTTPException(404,"Scan not found")
    a=db.query(ResearchAnnotation).filter(ResearchAnnotation.scan_id==payload.scan_id).first()
    if a:
        if user.role!="administrator" and a.created_by!=user.id:
            raise HTTPException(403,"Only the annotation creator or an administrator can update this review")
        a.ground_truth=payload.ground_truth;a.family=payload.family;a.dataset_source=payload.dataset_source.strip();a.notes=payload.notes
        action="research.annotation_updated"
    else:
        a=ResearchAnnotation(scan_id=payload.scan_id,ground_truth=payload.ground_truth,family=payload.family,dataset_source=payload.dataset_source.strip(),notes=payload.notes,created_by=user.id);db.add(a);action="research.annotation_created"
    db.flush();audit(db,user,action,a.id,{"scan_id":a.scan_id,"ground_truth":a.ground_truth});db.commit();db.refresh(a);return ann(a)
@router.delete("/annotations/{annotation_id}")
def delete_annotation(annotation_id:int,db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    a=db.get(ResearchAnnotation,annotation_id)
    if not a: raise HTTPException(404,"Annotation not found")
    if user.role!="administrator" and a.created_by!=user.id: raise HTTPException(403,"Only the creator or an administrator can remove this annotation")
    audit(db,user,"research.annotation_deleted",a.id,{"scan_id":a.scan_id});db.delete(a);db.commit();return {"message":"Annotation removed"}
@router.get("/notes")
def notes(db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    q=db.query(ExperimentNote).filter(ExperimentNote.user_id==user.id).order_by(desc(ExperimentNote.created_at)).limit(1000).all()
    return [{"id":n.id,"title":n.title,"content":n.content,"tags":n.tags,"created_at":n.created_at} for n in q]
@router.post("/notes")
def create_note(payload:ExperimentNoteCreate,db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    n=ExperimentNote(user_id=user.id,title=payload.title.strip(),content=payload.content.strip(),tags=payload.tags.strip());db.add(n);db.flush();audit(db,user,"research.note_created",n.id);db.commit();db.refresh(n);return {"id":n.id,"title":n.title,"content":n.content,"tags":n.tags,"created_at":n.created_at}
@router.delete("/notes/{note_id}")
def delete_note(note_id:int,db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    n=db.get(ExperimentNote,note_id)
    if not n: raise HTTPException(404,"Note not found")
    if user.role!="administrator" and n.user_id!=user.id: raise HTTPException(403,"You can only remove your own notes")
    audit(db,user,"research.note_deleted",n.id)
    db.delete(n);db.commit();return {"message":"Note removed"}
@router.get("/summary")
def summary(db:Session=Depends(get_db),user:User=Depends(require_roles(*ROLES))):
    anns=db.query(ResearchAnnotation).all(); labels={k:sum(a.ground_truth==k for a in anns) for k in ["benign","malware","unknown"]}
    # Accuracy metrics are intentionally not inferred from labels alone; predictions are only compared when both sides exist.
    paired=[]
    for a in anns:
        scan=db.get(Scan,a.scan_id); pred=(scan.result_json or {}).get("ml_prediction",{}) if scan else {}
        if a.ground_truth in {"benign","malware"} and pred.get("available") and pred.get("label"):
            actual=a.ground_truth; predicted="malware" if str(pred["label"]).lower()=="malware" else "benign"
            paired.append({"actual":actual,"predicted":predicted})
    return {"annotations":len(anns),"labels":labels,"paired_labeled_predictions":len(paired),"correct":sum(x["actual"]==x["predicted"] for x in paired),"limitation":"These counts are exploratory and potentially biased; use a pre-defined independent holdout set before reporting model metrics."}
