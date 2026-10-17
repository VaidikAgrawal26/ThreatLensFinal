# ThreatLens inert test fixtures

These are synthetic, harmless files for testing static upload and YARA workflows. They are not malware and are not representative training samples. Do not execute the PE canary.

- `threatlens_clean_demo.dat`: plain-text control fixture; should produce no match for the bundled `ThreatLens_Demo_Suspicious_API_Strings` rule. Model inference is unavailable for `.dat` because the candidate model supports `.exe` PE input only.
- `threatlens_yara_trigger_demo.dat`: inert text containing the three marker strings used by the bundled illustrative YARA rule; should produce that demo rule match. It does not contain API calls or malicious behavior. Model inference is unavailable for `.dat`.
- `threatlens_inert_pe_canary.exe`: minimal, parser-readable PE canary with an MZ/PE header, no executable-image flag, zero entry point, no imports, no code, and only inert marker strings in `.rdata`. It should exercise PE parsing and trigger the illustrative YARA rule. In the current local candidate model and scikit-learn 1.9.1 environment, it produced a **Benign partial estimate** (24/72 features observed). That output is fixture-specific and is not a malware detection test or ground truth.

The synthetic demo-indicator panel shown by the app is separate from extracted evidence and does not affect the score. Runtime model predictions can vary if the active model or dependencies change.

Regenerate the fixtures from this directory with:

```powershell
..\.venv\Scripts\python.exe .\generate_fixtures.py
```

From another working directory, use the project-root path to `.venv\Scripts\python.exe` instead. Upload the files through the authenticated Live Scan page. The application processes bytes without executing uploaded files.
