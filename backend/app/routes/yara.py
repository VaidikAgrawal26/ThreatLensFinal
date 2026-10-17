from pathlib import Path, PurePosixPath
from datetime import datetime, timezone
import hashlib, json, re, zipfile, io
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from app.core.config import settings
from app.core.security import get_current_user, require_roles
from app.db import get_db
from app.models import AuditLog, User
from sqlalchemy.orm import Session

router=APIRouter(prefix="/api/yara",tags=["YARA"],dependencies=[Depends(get_current_user)])
def _root():
    p=Path(settings.yara_rules_dir)
    if not p.is_absolute(): p=Path.cwd()/p
    p.mkdir(parents=True,exist_ok=True)
    return p.resolve()
def _inventory_file(f, root):
    item={"filename":str(f.relative_to(root)).replace("\\","/"),"bytes":f.stat().st_size,"compile_status":"not_checked","rule_count":None,"error":None,"definitions":[]}
    try:
        import yara
        compiled=yara.compile(filepath=str(f)); item["compile_status"]="ok"
        try:
            defs=[]
            for r in compiled.rules:
                defs.append({"name":r.identifier,"namespace":getattr(r,"namespace","default"),"tags":list(getattr(r,"tags",[]) or []),"meta":dict(getattr(r,"meta",{}) or {})})
            item["definitions"]=defs; item["rule_count"]=len(defs)
        except Exception: item["rule_count"]=None
    except Exception as exc: item["compile_status"]="error"; item["error"]=f"{type(exc).__name__}: {exc}"
    return item
@router.get("/rules")
def rules():
    root=_root(); files=sorted([f for f in root.rglob('*') if f.is_file() and f.suffix.lower() in {'.yar','.yara'}]); results=[_inventory_file(f,root) for f in files]
    total=sum(r["rule_count"] or 0 for r in results if r["compile_status"]=="ok")
    return {"count":len(files),"total_rules":total,"rules":results,"engine":"yara-python","source_policy":"Local files only. Each file should carry its upstream source, version and license in metadata/adjacent manifest; these are not guessed by the API.","note":"This endpoint does not download an upstream ruleset automatically."}
@router.post("/rules")
async def add_rule(file:UploadFile=File(...),db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    name=Path(file.filename or "").name
    if Path(name).suffix.lower() not in {".yar",".yara"}: raise HTTPException(415,"Only .yar or .yara rule files are accepted")
    if not name or name in {".",".."}: raise HTTPException(400,"Invalid filename")
    data=await file.read(1_000_001)
    if not data: raise HTTPException(400,"Rule file is empty")
    if len(data)>1_000_000: raise HTTPException(413,"Rule file exceeds 1 MB")
    try: text=data.decode("utf-8-sig")
    except UnicodeDecodeError: raise HTTPException(400,"Rule file must be UTF-8 text")
    try:
        import yara
        yara.compile(source=text)
    except ImportError: raise HTTPException(503,"yara-python is not installed; install backend requirements first")
    except Exception as exc: raise HTTPException(422,detail=f"YARA compilation failed: {type(exc).__name__}: {exc}")
    root=_root(); target=(root/name).resolve()
    if target.parent!=root: raise HTTPException(400,"Invalid rule path")
    if target.exists(): raise HTTPException(409,"A rule file with that name already exists; remove or rename it first")
    target.write_text(text,encoding="utf-8")
    db.add(AuditLog(user_id=actor.id,actor_email=actor.email,action="yara.rule_added",target=name,details={"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}));db.commit()
    return {"message":"Rule compiled and added. Review source/version/license before operational use.","filename":name,"bytes":len(data)}

@router.post("/ruleset")
async def import_ruleset(file:UploadFile=File(...),source:str=Form(...),version:str=Form(...),license_name:str=Form(...),db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    """Import a reviewed community/vendor rule ZIP; validate all rules before writing any."""
    if not (file.filename or "").lower().endswith(".zip"): raise HTTPException(415,"Upload a ZIP archive containing .yar/.yara files")
    if not source.strip() or not version.strip() or not license_name.strip(): raise HTTPException(422,"Source, version/revision and license are required")
    archive=await file.read(20_000_001)
    if len(archive)>20_000_000: raise HTTPException(413,"Compressed ruleset exceeds 20 MB")
    try: zf=zipfile.ZipFile(io.BytesIO(archive))
    except zipfile.BadZipFile: raise HTTPException(400,"Invalid ZIP archive")
    entries=[]; total=0
    for info in zf.infolist():
        if info.is_dir(): continue
        path=PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or "\\" in info.filename: raise HTTPException(400,"ZIP contains an unsafe path")
        if path.suffix.lower() not in {".yar",".yara"}: continue
        if info.file_size>1_000_000: raise HTTPException(413,f"Rule file {path.name} exceeds 1 MB")
        total+=info.file_size
        if total>50_000_000: raise HTTPException(413,"Expanded rule files exceed 50 MB")
        if len(entries)>=500: raise HTTPException(413,"Ruleset contains more than 500 rule files")
        entries.append((str(path),zf.read(info)))
    if not entries: raise HTTPException(400,"ZIP contains no .yar/.yara files")
    try: import yara
    except ImportError: raise HTTPException(503,"yara-python is not installed; install backend requirements first")
    staged=[]
    for rel,data in entries:
        try: text=data.decode("utf-8-sig")
        except UnicodeDecodeError: raise HTTPException(422,f"Rule file {rel} is not UTF-8 text")
        try: compiled=yara.compile(source=text); rule_count=len(compiled.rules)
        except Exception as exc: raise HTTPException(422,detail=f"Rule compilation failed for {rel}: {type(exc).__name__}: {exc}")
        staged.append((rel,text,rule_count,hashlib.sha256(data).hexdigest()))
    slug=re.sub(r"[^A-Za-z0-9_.-]+","_",source.strip()).strip("._-")[:40] or "ruleset"
    rev=re.sub(r"[^A-Za-z0-9_.-]+","_",version.strip()).strip("._-")[:40] or "version"
    root=_root(); target=(root/"imports"/f"{slug}_{rev}").resolve()
    if root not in target.parents: raise HTTPException(400,"Invalid ruleset target")
    if target.exists(): raise HTTPException(409,"This source/version ruleset is already installed")
    target.mkdir(parents=True,exist_ok=False)
    try:
        installed=[]
        for rel,text,rule_count,digest in staged:
            dest=(target/rel).resolve()
            if target not in dest.parents: raise ValueError("Unsafe rule path")
            dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(text,encoding="utf-8")
            installed.append({"file":rel,"rule_count":rule_count,"sha256":digest})
        manifest={"source":source.strip(),"version":version.strip(),"license":license_name.strip(),"imported_at":datetime.now(timezone.utc).isoformat(),"files":installed}
        (target/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")
    except Exception:
        import shutil;shutil.rmtree(target,ignore_errors=True);raise HTTPException(500,"Ruleset import failed; partial files were removed")
    db.add(AuditLog(user_id=actor.id,actor_email=actor.email,action="yara.ruleset_imported",target=slug,details={"version":rev,"license":license_name.strip(),"file_count":len(installed),"rule_count":sum(x["rule_count"] for x in installed)}));db.commit()
    return {"message":"Ruleset validated and imported","directory":str(target.relative_to(root)).replace("\\","/"),"source":manifest["source"],"version":manifest["version"],"license":manifest["license"],"file_count":len(installed),"rule_count":sum(x["rule_count"] for x in installed),"manifest":manifest}

@router.get("/rulesets")
def rulesets():
    root=_root(); out=[]
    for p in sorted((root/"imports").glob("*/manifest.json")) if (root/"imports").exists() else []:
        try: out.append(json.loads(p.read_text(encoding="utf-8")))
        except Exception: out.append({"directory":str(p.parent.relative_to(root)),"error":"Manifest could not be parsed"})
    return {"count":len(out),"rulesets":out}

@router.delete("/rules/{filename:path}")
def delete_rule(filename:str,db:Session=Depends(get_db),actor:User=Depends(require_roles("administrator"))):
    if Path(filename).suffix.lower() not in {".yar",".yara"} or ".." in Path(filename).parts: raise HTTPException(400,"Invalid rule filename")
    root=_root(); target=(root/filename).resolve()
    if root not in target.parents: raise HTTPException(400,"Invalid rule path")
    if not target.is_file(): raise HTTPException(404,"Rule file not found")
    target.unlink()
    db.add(AuditLog(user_id=actor.id,actor_email=actor.email,action="yara.rule_removed",target=filename,details={}));db.commit()
    return {"message":"Rule file removed from local ruleset","filename":filename}
