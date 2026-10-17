"""Strict ML inference adapter: never fabricates features to satisfy a model."""
from __future__ import annotations
import json
import re
from numbers import Integral, Real
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
_categories: dict[str, list[str]] | None = None


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
    global _model, _schema, _categories
    _model = None
    _schema = None
    _categories = None


def _model_categories(model: Any) -> dict[str, list[str]]:
    """Read the fitted OneHotEncoder vocabulary for the active pipeline."""
    global _categories
    if _categories is not None:
        return _categories
    found: dict[str, list[str]] = {}
    pre = getattr(model, "named_steps", {}).get("preprocessor")
    for _, transformer, columns in getattr(pre, "transformers_", []) or []:
        steps = getattr(transformer, "named_steps", {})
        encoder = steps.get("onehot")
        if encoder is None:
            continue
        for name, values in zip(columns, encoder.categories_):
            found[str(name)] = [str(v) for v in values]
    _categories = found
    return found


def _category_number(value: Any) -> float | None:
    """Parse training categories such as 0x00000400 or 0x1000 (Section: .text)."""
    text = str(value).strip()
    if text == "0":
        return 0.0
    match = re.match(r"^0x([0-9a-fA-F]+)", text)
    if match:
        return float(int(match.group(1), 16))
    if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _fitted_category(name: str, value: Any, categories: list[str]) -> Any:
    """Convert extracted PE values to the trained categorical representation."""
    if value is None or (isinstance(value, Real) and not np.isfinite(value)):
        return np.nan
    if isinstance(value, str) and value in categories:
        return value

    numeric = int(value) if isinstance(value, Integral) else None
    if numeric is not None:
        if name == "MachineType":
            known = {0x014C: "Intel 386 or later, and compatibles", 0x8664: "AMD AMD64"}
            return known.get(numeric, "Unknown (0)" if "Unknown (0)" in categories else str(value))
        if name == "Subsystem":
            try:
                import pefile
                enum_name = pefile.SUBSYSTEM_TYPE.get(numeric)
                if enum_name in categories:
                    return enum_name
            except Exception:
                pass
        if name == "Magic":
            enum_name = {0x10B: "PE32", 0x20B: "PE32+"}.get(numeric)
            if enum_name in categories:
                return enum_name
        if name == "magic_number":
            enum_name = "MZ" if numeric == 0x5A4D else None
            if enum_name in categories:
                return enum_name
        if name in {"DllCharacteristics", "text_Characteristics", "rdata_Characteristics"}:
            try:
                import pefile
                mapping = pefile.DLL_CHARACTERISTICS if name == "DllCharacteristics" else pefile.SECTION_CHARACTERISTICS
                flags = sorted({label for mask, label in mapping.items() if isinstance(mask, int) and mask and numeric & mask})
                encoded = str(flags) if flags else "0"
                if encoded in categories:
                    return encoded
            except Exception:
                pass
        matches = [item for item in categories if _category_number(item) == float(numeric)]
        if matches:
            if numeric == 0 and "0" in matches:
                return "0"
            return matches[0]
        # Unseen numeric categories are valid strings for OneHotEncoder(handle_unknown='ignore').
        return f"0x{numeric:x}"

    if isinstance(value, Real):
        numeric = float(value)
        matches = [item for item in categories if _category_number(item) == numeric]
        if matches:
            return matches[0]
        return str(value)
    return str(value)


def _runtime_compatibility_error() -> str | None:
    """The selected Random Forest pipeline was serialized with scikit-learn 1.9.1.

    sklearn does not promise cross-version pickle compatibility. Do not advertise
    inference as ready unless the runtime exactly matches the serialized version.
    """
    try:
        import sklearn
        if str(sklearn.__version__) != "1.9.1":
            return f"The active Random Forest was serialized with scikit-learn 1.9.1; runtime has {sklearn.__version__}. Install the pinned backend requirements before inference."
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
        "note": "The active Random Forest and its 72-column schema are checked at readiness. Its fitted median/mode imputers allow static scans to run when runtime telemetry is absent; those values are inferred from training statistics, not observed behavior. Partial-input predictions require analyst review and readiness does not establish accuracy.",
        "active_model": "User-supplied Random Forest",
        "partial_input_policy": "Use the pipeline's fitted numeric median and categorical most-frequent imputers; mark every such prediction as partial and expose missing runtime fields.",
    }


def predict(features: dict):
    global _model
    if not MODEL_PATH.exists():
        return {"available": False, "label": None, "score": None, "detail": "A trained model artifact is not installed.", "missing_features": []}
    try:
        schema = _load_schema()
        if schema is None:
            return {"available": False, "label": None, "score": None, "detail": "The model feature schema is not installed.", "missing_features": []}
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
        missing = [name for name in schema if name not in features or features[name] is None]
        missing_core = sorted(core_fields.intersection(missing))
        missing_runtime = sorted(runtime_fields.intersection(missing))
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
        categories = _model_categories(_model)
        extension_categories = categories.get("file_extension", [])
        extension = str(features.get("file_extension", "")).strip().lower().lstrip(".")
        if extension_categories and extension not in extension_categories:
            return {
                "available": False, "label": None, "score": None,
                "detail": "The active model was trained on .exe samples only; ML inference was skipped for this extension. Static/YARA analysis still completed.",
                "missing_features": [], "unsupported_file_extension": extension,
                "supported_file_extensions": extension_categories,
            }
        row_values = {name: (features[name] if name in features and features[name] is not None else np.nan) for name in schema}
        unseen_categories: list[str] = []
        for name, vocabulary in categories.items():
            if name in row_values:
                row_values[name] = _fitted_category(name, row_values[name], vocabulary)
                value = row_values[name]
                if not (isinstance(value, Real) and not np.isfinite(value)) and str(value) not in vocabulary:
                    unseen_categories.append(name)
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
        observed_count = len(schema) - len(missing)
        coverage = round(100.0 * observed_count / len(schema), 1)
        categorical_expected = len(categories)
        categorical_coverage = round(100.0 * (categorical_expected - len(unseen_categories)) / categorical_expected, 1) if categorical_expected else 100.0
        partial = bool(missing or unseen_categories)
        warnings = []
        if missing:
            warnings.append(f"{len(missing)} of {len(schema)} inputs were absent and filled by fitted training-time imputers")
        if unseen_categories:
            warnings.append(f"{len(unseen_categories)} categorical values were outside the training vocabulary and ignored by the fitted encoder")
        detail = (
            "Partial static estimate: " + "; ".join(warnings) + "; runtime behavior was not observed. Corroborate this result with file evidence."
            if partial else None
        )
        return {
            "available": True, "label": label, "score": score, "detail": detail,
            "missing_features": missing, "runtime_features_missing": missing_runtime,
            "unseen_categorical_values": unseen_categories,
            "feature_count": len(schema), "available_feature_count": observed_count,
            "input_coverage": {"observed": observed_count, "expected": len(schema), "percent": coverage, "partial": partial, "unseen_category_count": len(unseen_categories), "categorical_recognized": categorical_expected-len(unseen_categories), "categorical_expected": categorical_expected, "categorical_percent": categorical_coverage},
            "inference_mode": "partial_static_with_training_imputation" if partial else "complete_schema",
            "interpretation_warning": "Random Forest output is not calibrated. Missing inputs use the model's fitted median/mode imputers; no runtime behavior was collected, and this score is not proof of malware or safety.",
        }
    except Exception as exc:
        return {"available": False, "label": None, "score": None, "detail": f"Model/schema inference failed safely ({type(exc).__name__}).", "missing_features": []}
