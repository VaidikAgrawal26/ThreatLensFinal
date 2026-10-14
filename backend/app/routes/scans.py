from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.db import get_db
from app.core.security import get_current_user, require_roles
from app.models import Scan, AuditLog
from app.core.config import settings
from app.services.static_analyzer import analyze_file
router=APIRouter(prefix="/api/scans",tags=["Scans"],dependencies=[Depends(get_current_user)])
ALLOWED={".exe",".dll",".sys",".scr",".ocx",".bin",".dat",".pdf",".zip"}
@router.post("/upload")
async def upload(file: UploadFile=File(...), db: Session=Depends(get_db), actor=Depends(require_roles("administrator", "security_analyst", "researcher"))):
    name=file.filename or "upload.bin"
    ext="."+name.rsplit(".",1)[-1].lower() if "." in name else ""
    if not ext or ext not in ALLOWED: raise HTTPException(415,detail=f"Unsupported or missing extension {ext or '(none)'}; allowed: {', '.join(sorted(ALLOWED))}")
    data=await file.read(settings.max_upload_mb*1024*1024+1)
    if len(data)>settings.max_upload_mb*1024*1024: raise HTTPException(413,detail="Upload exceeds configured size limit")
    if not data: raise HTTPException(400,detail="Empty file")
    result=analyze_file(name,data)
    row=Scan(filename=result["filename"],sha256=result["sha256"],md5=result["md5"],file_size=result["file_size"],file_type=result["file_type"],verdict=result["verdict"],severity=result["severity"],risk_score=result["risk_score"],ml_label=(result.get("ml_prediction") or {}).get("label"),ml_score=(result.get("ml_prediction") or {}).get("score"),yara_count=len(result.get("yara_matches",[])),result_json=result)
    db.add(row); db.flush()
    # Audit evidence without storing uploaded file contents or secrets.
    db.add(AuditLog(user_id=actor.id, actor_email=actor.email, action="scan.completed", target=str(row.id), details={"filename":row.filename,"sha256":row.sha256,"verdict":row.verdict,"severity":row.severity}))
    db.commit(); db.refresh(row)
    return {"scan_id":row.id,**result,"created_at":row.created_at}
@router.get("")
def history(limit:int=100,db:Session=Depends(get_db)):
    return [{"id":r.id,"filename":r.filename,"sha256":r.sha256,"file_size":r.file_size,"file_type":r.file_type,"verdict":r.verdict,"severity":r.severity,"risk_score":r.risk_score,"ml_label":r.ml_label,"ml_score":r.ml_score,"yara_count":r.yara_count,"features":(r.result_json or {}).get("features",{}),"ml_prediction":(r.result_json or {}).get("ml_prediction",{}),"created_at":r.created_at} for r in db.query(Scan).order_by(desc(Scan.id)).limit(max(1,min(limit,500))).all()]
@router.get("/{scan_id}")
def detail(scan_id:int,db:Session=Depends(get_db)):
    r=db.query(Scan).filter(Scan.id==scan_id).first()
    if not r: raise HTTPException(404,detail="Scan not found")
    return {"id":r.id,**r.result_json,"created_at":r.created_at}
