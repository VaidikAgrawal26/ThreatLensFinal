# Automated backend tests

Run from `backend/` after installing `requirements.txt`:

```powershell
python -m pytest -q
```

Tests cover basic static-analysis output, entropy edge cases, structured YARA status, and strict ML schema handling. They do **not** claim to prove detection efficacy, validate an external trained model, or replace live YARA integration tests. Test behavior depends on installed optional analysis dependencies.
