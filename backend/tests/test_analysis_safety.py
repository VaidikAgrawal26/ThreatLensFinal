import json
from pathlib import Path
import pytest
from app.services import ml_service
from app.services.static_analyzer import analyze_file, entropy, yara_scan


def test_entropy_empty_and_constant():
    assert entropy(b"") == 0.0
    assert entropy(b"aaaa") == 0.0


def test_analyze_file_reports_hashes_and_disclaimer():
    result = analyze_file("sample.bin", b"harmless sample content for static analysis")
    assert len(result["sha256"]) == 64
    assert len(result["md5"]) == 32
    assert result["file_size"] == len(b"harmless sample content for static analysis")
    assert "does not prove safety" in result["disclaimer"]
    assert "yara_summary" in result and "ml_prediction" in result


def test_static_file_extension_is_available_but_runtime_features_are_not_fabricated():
    result = analyze_file("report.exe", b"not a PE executable; harmless fixture")
    assert result["features"]["file_extension"] == "exe"
    # Static bytes alone do not establish runtime registry/network/process behaviour.
    assert "registry_read" not in result["features"]
    assert "network_threats" not in result["features"]
    assert result["ml_prediction"]["available"] is False


def test_ml_does_not_fabricate_missing_features(tmp_path, monkeypatch):
    model = tmp_path / "model.pkl"
    model.write_bytes(b"placeholder artifact; must not be loaded when required features are absent")
    schema = tmp_path / "feature_schema.json"
    schema.write_text(json.dumps({"feature_names": ["file_size", "registry_read", "network_threats"]}), encoding="utf-8")
    monkeypatch.setattr(ml_service, "MODEL_PATH", model)
    monkeypatch.setattr(ml_service, "SCHEMA_PATH", schema)
    ml_service.reset_model_cache()
    result = ml_service.predict({"file_size": 42})
    assert result["available"] is False
    assert set(result["missing_features"]) == {"registry_read", "network_threats"}
    assert "inventing values" in result["detail"]
    ml_service.reset_model_cache()


def test_schema_rejects_duplicate_names(tmp_path, monkeypatch):
    schema = tmp_path / "feature_schema.json"
    schema.write_text(json.dumps({"features": ["a", "a"]}), encoding="utf-8")
    monkeypatch.setattr(ml_service, "SCHEMA_PATH", schema)
    ml_service.reset_model_cache()
    with pytest.raises(ValueError, match="duplicate"):
        ml_service._load_schema()
    ml_service.reset_model_cache()


def test_yara_scan_returns_structured_status():
    matches, error, summary = yara_scan(b"benign fixture")
    assert isinstance(matches, list)
    assert summary["status"] in {"no_rules", "engine_unavailable", "completed", "partial_errors"}
    assert "rules_evaluated" in summary


def test_model_schema_supports_training_notebook_format(tmp_path, monkeypatch):
    schema = tmp_path / 'feature_schema.json'
    schema.write_text(json.dumps({'feature_columns_in_input_order': ['a', 'b']}), encoding='utf-8')
    monkeypatch.setattr(ml_service, 'SCHEMA_PATH', schema)
    ml_service.reset_model_cache()
    assert ml_service._load_schema() == ['a', 'b']
    ml_service.reset_model_cache()


def test_risk_components_are_reported_and_capped():
    result = analyze_file('sample.bin', b'harmless sample fixture')
    assert sum(result['risk_components'].values()) == result['risk_score']
    assert result['risk_components']['yara_evidence'] <= 30
    assert 'not a calibrated probability' in result['risk_method']


def test_demo_yara_positive_fixture_when_engine_installed():
    try:
        import yara  # noqa: F401
    except ImportError:
        pytest.skip('yara-python is not installed in this test environment')
    fixture = Path(__file__).parent / 'fixtures' / 'yara_positive.bin'
    result = analyze_file(fixture.name, fixture.read_bytes())
    assert any(m['rule'] == 'ThreatLens_Demo_Suspicious_API_Strings' for m in result['yara_matches'])


def test_demo_yara_negative_fixture_when_engine_installed():
    try:
        import yara  # noqa: F401
    except ImportError:
        pytest.skip('yara-python is not installed in this test environment')
    fixture = Path(__file__).parent / 'fixtures' / 'yara_negative.bin'
    result = analyze_file(fixture.name, fixture.read_bytes())
    assert not any(m['rule'] == 'ThreatLens_Demo_Suspicious_API_Strings' for m in result['yara_matches'])
