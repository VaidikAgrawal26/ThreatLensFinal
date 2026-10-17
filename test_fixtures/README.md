# ThreatLens inert test fixtures

These are synthetic, harmless files for testing static upload and YARA workflows. They are not malware and are not representative training samples. Do not execute the PE canary.

- `threatlens_clean_demo.dat`: plain-text control fixture; no YARA match is expected until you install rules. Model inference is unavailable for `.dat` because the candidate model supports `.exe` PE input only.
- `threatlens_yara_trigger_demo.dat`: inert text containing inert marker strings used only by the isolated automated YARA test rule under `backend/tests/fixtures/rules/`; that rule is not deployed. It does not contain API calls or malicious behavior. Model inference is unavailable for `.dat`.
- `threatlens_inert_pe_canary.exe`: minimal, parser-readable PE canary with an MZ/PE header, no executable-image flag, zero entry point, no imports, no code, and only inert marker strings in `.rdata`. It exercises PE parsing and static feature extraction; production YARA remains empty unless reviewed rules are installed. In the current local candidate model and scikit-learn 1.9.1 environment, it produced a **Benign partial estimate** (48/72 features observed). That output is fixture-specific and is not a malware detection test or ground truth.

These files are test fixtures only. The application does not display synthetic indicators or add their strings to extracted results. Runtime model predictions can vary if the active model or dependencies change.

Regenerate the fixtures from this directory with:

```powershell
..\.venv\Scripts\python.exe .\generate_fixtures.py
```

From another working directory, use the project-root path to `.venv\Scripts\python.exe` instead. Upload the files through the authenticated Live Scan page. The application processes bytes without executing uploaded files.
