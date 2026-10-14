from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
import csv, io
from app.db import get_db
from app.core.security import get_current_user
from app.models import Scan
router=APIRouter(prefix="/api/analytics",tags=["Analytics"],dependencies=[Depends(get_current_user)])
def rows(db): return db.query(Scan).order_by(desc(Scan.id)).limit(5000).all()
@router.get("/overview")
def overview(db:Session=Depends(get_db)):
    data=rows(db); n=len(data)
    severity={k:sum(x.severity==k for x in data) for k in ["low","medium","high","critical"]}
    verdict={}
    daily={}
    for x in data:
        verdict[x.verdict]=verdict.get(x.verdict,0)+1
        date=x.created_at.isoformat()[:10] if x.created_at else "unknown"
        daily[date]=daily.get(date,0)+1
    return {"total_scans":n,"malicious_suspected":sum(x.verdict=="malicious_suspected" for x in data),"suspicious":sum(x.verdict=="suspicious" for x in data),"high_risk":sum(x.severity in {"high","critical"} for x in data),"average_risk_score":round(sum(x.risk_score or 0 for x in data)/n,2) if n else 0,"severity_distribution":severity,"verdict_distribution":verdict,"daily_trend":[{"date":k,"scans":v} for k,v in sorted(daily.items())[-14:]],"recent_scans":[{"id":x.id,"filename":x.filename,"verdict":x.verdict,"severity":x.severity,"risk_score":x.risk_score,"yara_count":x.yara_count,"created_at":x.created_at} for x in data[:10]]}
@router.get("/notifications")
def notifications(db:Session=Depends(get_db)):
    items=[]
    for x in rows(db):
        if x.severity in {"high","critical"} or x.yara_count or x.verdict=="malicious_suspected":
            items.append({"id":x.id,"title":f"Threat scan: {x.filename}","severity":x.severity,"verdict":x.verdict,"risk_score":x.risk_score,"yara_count":x.yara_count,"created_at":x.created_at})
    return {"count":len(items),"items":items[:50]}
@router.get("/security-report")
def report(db:Session=Depends(get_db)):
    o=overview(db)
    return {"generated_at":datetime.now(timezone.utc).isoformat(),"summary":{k:o[k] for k in ["total_scans","malicious_suspected","suspicious","high_risk","average_risk_score"]},"severity_distribution":o["severity_distribution"],"verdict_distribution":o["verdict_distribution"],"recent_scans":o["recent_scans"],"limitations":"Static triage only; not a guarantee of malware detection."}
@router.get("/export.csv")
def export(db:Session=Depends(get_db)):
    b=io.StringIO(); w=csv.writer(b); w.writerow(["id","filename","sha256","verdict","severity","risk_score","ml_label","ml_score","yara_count","created_at"])
    for x in rows(db): w.writerow([x.id,x.filename,x.sha256,x.verdict,x.severity,x.risk_score,x.ml_label,x.ml_score,x.yara_count,x.created_at])
    b.seek(0)
    return StreamingResponse(iter([b.getvalue()]),media_type="text/csv",headers={"Content-Disposition":"attachment; filename=threatlens_scans.csv"})
