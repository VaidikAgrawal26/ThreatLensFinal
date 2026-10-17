from pathlib import PureWindowsPath

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy import desc
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.config import settings
from app.core.security import get_current_user, require_roles
from app.db import get_db
from app.models import AuditLog, Scan, User
from app.services.static_analyzer import analyze_file

router = APIRouter(prefix="/api/scans", tags=["Scans"], dependencies=[Depends(get_current_user)])
ALLOWED = {".exe", ".dll", ".sys", ".scr", ".ocx", ".bin", ".dat", ".pdf", ".zip"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ocx"}


def _validate_signature(extension: str, data: bytes) -> None:
    """Reject obvious extension/content mismatches without trusting client MIME headers."""
    if extension in EXECUTABLE_EXTENSIONS and not data.startswith(b"MZ"):
        raise HTTPException(415, "File content does not have a Windows PE/DOS header")
    if extension == ".pdf" and not data.startswith(b"%PDF-"):
        raise HTTPException(415, "File content does not have a PDF header")
    if extension == ".zip" and data[:4] not in {b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"}:
        raise HTTPException(415, "File content does not have a ZIP header")


def _summary(row: Scan) -> dict:
    result = row.result_json or {}
    return {
        "id": row.id, "filename": row.filename, "sha256": row.sha256,
        "file_size": row.file_size, "file_type": row.file_type,
        "verdict": row.verdict, "severity": row.severity,
        "risk_score": row.risk_score, "ml_label": row.ml_label,
        "ml_score": row.ml_score, "yara_count": row.yara_count,
        "features": result.get("features", {}),
        "ml_prediction": result.get("ml_prediction", {}),
        "created_at": row.created_at,
    }


@router.post("/upload")
async def upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    actor: User = Depends(require_roles("administrator", "security_analyst", "researcher")),
):
    raw_name = (file.filename or "upload.bin").replace("\\", "/")
    name = PureWindowsPath(raw_name).name.strip()
    if not name or name in {".", ".."}:
        raise HTTPException(400, "A valid filename is required")
    extension = PureWindowsPath(name).suffix.lower()
    if extension not in ALLOWED:
        raise HTTPException(415, detail=f"Unsupported file extension; allowed: {', '.join(sorted(ALLOWED))}")

    max_bytes = settings.max_upload_mb * 1024 * 1024
    try:
        data = await file.read(max_bytes + 1)
    finally:
        await file.close()
    if len(data) > max_bytes:
        raise HTTPException(413, "Upload exceeds the configured size limit")
    if not data:
        raise HTTPException(400, "Empty files cannot be analyzed")
    _validate_signature(extension, data)

    try:
        # PE parsing, rule matching, and feature extraction are CPU-bound; keep them off
        # the ASGI event loop so other requests can still be served.
        result = await run_in_threadpool(analyze_file, name, data)
        row = Scan(
            filename=result["filename"], sha256=result["sha256"], md5=result["md5"],
            file_size=result["file_size"], file_type=result["file_type"],
            verdict=result["verdict"], severity=result["severity"],
            risk_score=result["risk_score"],
            ml_label=(result.get("ml_prediction") or {}).get("label"),
            ml_score=(result.get("ml_prediction") or {}).get("score"),
            yara_count=len(result.get("yara_matches", [])), result_json=result,
            uploaded_by=actor.id,
        )
        db.add(row)
        db.flush()
        db.add(AuditLog(
            user_id=actor.id, actor_email=actor.email, action="scan.completed",
            target=str(row.id), details={"filename": row.filename, "sha256": row.sha256,
                                         "verdict": row.verdict, "severity": row.severity},
        ))
        db.commit()
        db.refresh(row)
    except HTTPException:
        db.rollback()
        raise
    except Exception as exc:
        db.rollback()
        raise HTTPException(422, f"File analysis failed safely: {type(exc).__name__}") from exc
    finally:
        # Uploaded bytes are kept only for the duration of analysis; the application
        # persists the evidence record, not the submitted sample itself.
        del data
    return {"scan_id": row.id, **result, "created_at": row.created_at}


@router.get("")
def history(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    rows = db.query(Scan).order_by(desc(Scan.id)).offset(offset).limit(limit).all()
    return [_summary(row) for row in rows]


@router.get("/{scan_id}")
def detail(scan_id: int, db: Session = Depends(get_db)):
    row = db.get(Scan, scan_id)
    if not row:
        raise HTTPException(404, detail="Scan not found")
    return {"id": row.id, **(row.result_json or {}), "created_at": row.created_at}
