"""Strict ML inference adapter: never fabricates features to satisfy a model."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
import joblib
import pandas as pd
import numpy as np
from app.core.config import settings


def _resolve(path_value: str) -> Path:
    p = Path(path_value)
    return p.resolve() if p.is_absolute() else (Path.cwd() / p).resolve()

MODEL_PATH = _resolve(settings.model_path)
SCHEMA_PATH = _resolve(settings.feature_schema_path)
_model: Any = None
_schema: list[str] | None = None


def _load_schema() -> list[str] | None:
    """Read supported schema formats; reject ambiguous or duplicate feature names."""
    global _schema
    if _schema is not None:
        return _schema
    if not SCHEMA_PATH.exists():
        return None
    raw = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        names = raw
    elif isinstance(raw, dict):
        names = (raw.get("feature_names") or raw.get("feature_columns_in_input_order") or raw.get("feature_columns") or raw.get("features") or raw.get("columns"))
        if isinstance(names, dict):
            names = list(names.keys())
        if isinstance(names, list) and names and isinstance(names[0], dict):
            names = [item.get("name") for item in names]
    else:
        names = None
    if not isinstance(names, list) or not names or not all(isinstance(x, str) and x.strip() for x in names):
        raise ValueError("feature_schema.json must contain a non-empty feature_names/features/columns list")
    if len(set(names)) != len(names):
        raise ValueError("feature_schema.json contains duplicate feature names")
    _schema = names
    return _schema


def reset_model_cache() -> None:
    """Test/admin helper: reload model and schema on the next prediction."""
    global _model, _schema
    _model = None
    _schema = None


def _runtime_compatibility_error() -> str | None:
    """The supplied pipeline was serialized with scikit-learn 1.9.0.

    sklearn does not promise cross-version pickle compatibility. Do not advertise
    inference as ready when the runtime is on another minor version.
    """
    try:
        import sklearn
        parts = str(sklearn.__version__).split(".")
        if parts[:2] != ["1", "9"]:
            return f"Model was serialized with scikit-learn 1.9.x; runtime has {sklearn.__version__}. Install the pinned backend requirements before inference."
    except Exception as exc:
        return f"Unable to determine scikit-learn runtime version: {exc}"
    return None


def readiness() -> dict:
    global _model
    schema = None
    schema_error = None
    model_error = None
    mismatch = False
    compatibility_error = _runtime_compatibility_error()
    try:
        schema = _load_schema()
    except Exception as exc:
        schema_error = str(exc)
    model_exists = MODEL_PATH.exists()
    if model_exists and schema is not None and schema_error is None and compatibility_error is None:
        try:
            if _model is None:
                _model = joblib.load(MODEL_PATH)  # Only load artifacts you trust.
            model_features = list(getattr(_model, "feature_names_in_", []))
            if model_features and model_features != schema:
                mismatch = True
                model_error = "Model feature_names_in_ order does not match feature_schema.json"
            n_features = getattr(_model, "n_features_in_", None)
            if n_features is not None and int(n_features) != len(schema):
                mismatch = True
                model_error = f"Model expects {int(n_features)} features but schema declares {len(schema)}"
        except Exception as exc:
            model_error = f"Model load failed: {type(exc).__name__}: {exc}"
    if compatibility_error and model_error is None:
        model_error = compatibility_error
    ready = bool(model_exists and schema is not None and schema_error is None and _model is not None and not mismatch and not model_error)
    return {
        "available": ready,
        "model_exists": model_exists,
        "model_loadable": bool(_model is not None),
        "model_path": str(MODEL_PATH),
        "schema_exists": SCHEMA_PATH.exists(),
        "schema_path": str(SCHEMA_PATH),
        "schema_feature_count": len(schema) if schema else None,
        "schema_error": schema_error,
        "model_error": model_error,
        "runtime_compatibility_error": compatibility_error,
        "schema_mismatch": mismatch,
        "note": "Ready means the artifact loaded and declared schema checks passed; it does not establish model accuracy or guarantee all live features are extractable for every file.",
    }


def predict(features: dict):
    global _model
    if not MODEL_PATH.exists():
        return {"available": False, "label": None, "score": None, "detail": f"Model artifact not found: {MODEL_PATH}", "missing_features": []}
    try:
        schema = _load_schema()
        if schema is None:
            return {"available": False, "label": None, "score": None, "detail": f"Feature schema not found: {SCHEMA_PATH}", "missing_features": []}
        runtime_fields = {
            "registry_read", "registry_write", "registry_delete", "registry_total",
            "network_threats", "network_dns", "network_http", "network_connections",
            "processes_malicious", "processes_suspicious", "processes_monitored", "total_procsses",
            "files_malicious", "files_suspicious", "files_text", "files_unknown",
        }
        # These core PE fields must be measured from the uploaded file. Other fields may
        # be missing for a legitimate reason (e.g. a section absent from the PE); the
        # supplied training pipeline includes imputers, so preserve missingness as NaN.
        core_fields = {
            "file_extension", "EntryPoint", "PEType", "MachineType", "Magic",
            "SizeOfCode", "AddressOfEntryPoint", "ImageBase", "SizeOfImage",
        }
        missing = [name for name in schema if name not in features]
        missing_core = sorted(core_fields.intersection(missing))
        required_missing = [name for name in missing if name not in runtime_fields]
        schema_has_core = bool(core_fields.intersection(schema))
        if missing_core or (not schema_has_core and missing):
            return {"available": False, "label": None, "score": None, "detail": "Required static features could not be extracted; inference was skipped instead of inventing values.", "missing_features": missing, "missing_core_features": missing_core, "required_feature_count": len(schema), "available_feature_count": sum(name in features for name in schema)}
        compatibility_error = _runtime_compatibility_error()
        if compatibility_error:
            return {"available": False, "label": None, "score": None, "detail": compatibility_error, "missing_features": [], "runtime_compatibility_error": compatibility_error}
        if _model is None:
            _model = joblib.load(MODEL_PATH)
        model_features = list(getattr(_model, "feature_names_in_", []))
        if model_features and model_features != schema:
            return {"available": False, "label": None, "score": None, "detail": "Model feature_names_in_ order does not match feature_schema.json; inference was skipped.", "missing_features": [], "schema_mismatch": True}
        row_values = {name: (features[name] if name in features and features[name] is not None else np.nan) for name in schema}
        row = pd.DataFrame([row_values], columns=schema)
        pred = _model.predict(row)[0]
        pred_text = str(pred).strip().lower()
        label = "Malware" if pred_text in {"1", "malware", "true", "malicious", "infected"} else "Benign" if pred_text in {"0", "benign", "false", "clean"} else str(pred)
        score = None
        classes = list(getattr(_model, "classes_", []))
        if hasattr(_model, "predict_proba"):
            proba = _model.predict_proba(row)[0]
            positive_index = next((i for i, c in enumerate(classes) if str(c).strip().lower() in {"1", "malware", "true", "malicious", "infected"}), None)
            if positive_index is not None and positive_index < len(proba):
                score = float(proba[positive_index])
            elif len(proba) == 2 and not classes:
                score = float(proba[1])
        missing_runtime = sorted(runtime_fields.intersection(missing))
        detail = "Runtime telemetry was unavailable and imputed by the saved training pipeline; interpret this as a static-feature estimate, not a behavioral analysis." if missing_runtime else None
        return {"available": True, "label": label, "score": score, "detail": detail, "missing_features": missing, "runtime_features_missing": missing_runtime, "feature_count": len(schema), "schema_path": str(SCHEMA_PATH), "interpretation_warning": "The score is model output, not a calibrated probability or proof of malware."}
    except Exception as exc:
        return {"available": False, "label": None, "score": None, "detail": f"Model/schema/inference error: {type(exc).__name__}: {exc}", "missing_features": []}
