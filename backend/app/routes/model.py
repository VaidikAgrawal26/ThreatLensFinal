from pathlib import Path
import csv
import json
from fastapi import APIRouter, Depends
from app.core.config import settings
from app.services.ml_service import readiness
from app.core.security import get_current_user

router = APIRouter(prefix="/api/model", tags=["Model"], dependencies=[Depends(get_current_user)])

def _artifact_path(name: str) -> Path:
    base = Path(settings.model_path)
    if not base.is_absolute():
        base = Path.cwd() / base
    return base.resolve().parent / name

@router.get("/readiness")
def model_readiness():
    result = readiness()
    metrics_path = _artifact_path("metrics.json")
    result["evaluation_metrics_available"] = metrics_path.exists()
    result["evaluation_metrics_path"] = str(metrics_path)
    return result

@router.get("/evaluation")
def model_evaluation():
    """Return saved training evaluation artifacts; these are not live scan accuracy."""
    metrics_path = _artifact_path("metrics.json")
    comparison_path = _artifact_path("model_comparison.csv")
    report_path = _artifact_path("classification_report.txt")
    importance_path = _artifact_path("feature_importance_top100.csv")
    payload = {"source": "saved training artifacts", "applies_to_live_scans": False, "metrics": None, "model_comparison": [], "classification_report": None, "feature_importance_top100": []}
    if metrics_path.exists():
        try: payload["metrics"] = json.loads(metrics_path.read_text(encoding="utf-8"))
        except Exception as exc: payload["metrics_error"] = str(exc)
    if comparison_path.exists():
        try:
            with comparison_path.open(encoding="utf-8-sig", newline="") as f: payload["model_comparison"] = list(csv.DictReader(f))
        except Exception as exc: payload["model_comparison_error"] = str(exc)
    if report_path.exists(): payload["classification_report"] = report_path.read_text(encoding="utf-8")
    if importance_path.exists():
        try:
            with importance_path.open(encoding="utf-8-sig", newline="") as f: payload["feature_importance_top100"] = list(csv.DictReader(f))
        except Exception as exc: payload["feature_importance_error"] = str(exc)
    payload["artifact_consistency_note"] = "The supplied metrics.json and classification_report.txt contain different reported accuracies (99.55% and 99.10%). They are preserved as provided; verify the evaluation run before publication."
    return payload
