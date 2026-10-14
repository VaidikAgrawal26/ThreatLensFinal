# ThreatLens AI — Static Malware Triage Workbench

ThreatLens AI is a local web application for static file triage. It computes hashes, extracts available static indicators, scans locally installed YARA rules, attempts compatible ML inference, stores scan history, and provides role-specific views and scan-derived analytics. Uploaded files are read as bytes and are not intentionally executed.

> **Scope warning:** this is not a sandbox, runtime endpoint monitor, full SOC/incident platform or guarantee of malware detection. Risk scores are heuristic, YARA matches can false-positive, and an unavailable model must not be treated as a benign result.

## Windows quick start

1. Install Python 3.11+ and Node.js LTS.
2. In PowerShell at the project root:
   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   cd backend
   python -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```
3. Edit `backend/.env` before first startup. Set `JWT_SECRET` to a long, unique random value. To create the first administrator, set `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` to your own values. The admin is created only if the email is not already in the database. Remove the bootstrap password from the environment after account creation.
4. Start the API from `backend`:
   ```powershell
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
   ```
5. In a second PowerShell terminal, from `frontend`:
   ```powershell
   npm install
   npm run dev
   ```
6. Open the URL printed by Vite. Default API: `http://127.0.0.1:8001`; API docs: `http://127.0.0.1:8001/docs`.

If Vite chooses a port other than 5173/5174, add the exact origin to `CORS_ORIGINS` in `backend/.env` and restart the backend. The frontend API URL can be overridden in `frontend/.env.local` using `VITE_API_URL`.

## Docker option

Copy `backend/.env.example` to `backend/.env`, set a unique `JWT_SECRET`, and configure the first administrator credentials. Then run `docker compose up --build` from the project root. The compose setup uses port 8000 for the API and 5173 for the frontend; confirm that those ports are free.

## Authentication and roles
- Signup displays all four roles: Administrator, Security Analyst, SOC Team Member, and Researcher. The role is stored server-side and the login selection must match the saved role.
- Researcher signups activate immediately; Administrator, Security Analyst, and SOC Team Member signups remain pending until an administrator activates them. Bootstrap the first administrator using the environment variables above.
- Only administrators can change roles/status, view audit events, manage accounts, and add/remove local YARA rule files.
- File uploads are allowed for Administrator, Security Analyst, and Researcher roles. SOC Team Members can monitor scan history, alerts and incidents but cannot upload files. Scan, history, analytics, YARA inventory and model-readiness APIs require a signed bearer token.
- This is still a prototype: configure HTTPS, rate limiting, strong secrets, retention policies, protected backups and external audit-log storage before deployment.

## ML artifact
Copy your trusted, actual training output to `backend/ml/artifacts/malware_classifier.pkl` and the matching `feature_schema.json` beside it. Do not rename another model to this name. The schema reader supports the training notebook's `feature_columns_in_input_order` field and common alternatives. PE header/section/import features are extracted when `pefile` is installed. Runtime-only features are not invented; incompatible models are marked unavailable. See [ML Model Integration](docs/ML_MODEL_INTEGRATION.md).

The supplied model artifact and matching schema are included. Live inference still depends on installing the pinned requirements (including scikit-learn 1.9.x), compatible artifact loading, and the uploaded file containing extractable required static features. Runtime telemetry is not fabricated.

## YARA rules
Only `backend/yara_rules/threatlens_demo.yar` is bundled by default. It is an illustrative test rule, not a maintained production ruleset. The Administrator → Rule Updates page allows reviewed local `.yar`/`.yara` files to be compiled and added or removed. No upstream ruleset is auto-downloaded. Verify source, version, license and performance before operational use. See [YARA Library and Mapping](docs/YARA_LIBRARY_AND_MAPPING.md).

## Test and verify
```powershell
cd backend
python -m compileall -q app tests
python -m pytest -q
```
The frontend JSX was syntax-transpiled with TypeScript in the packaging environment, but a full Vite production build could not be run there because npm dependencies were unavailable. After installing frontend dependencies, run `npm run build` from `frontend`.

## Documentation
- [Architecture and Threat Model](docs/ARCHITECTURE.md)
- [API Reference](docs/API_REFERENCE.md)
- [ML Model Integration](docs/ML_MODEL_INTEGRATION.md)
- [Dashboard Analytics](docs/DASHBOARD_ANALYTICS.md)
- [Testing Guide](docs/TESTING.md)
- [Role Functionality Inventory](docs/ROLE_FUNCTIONALITY_AND_ANALYTICS.md)
- [YARA Library and Mapping](docs/YARA_LIBRARY_AND_MAPPING.md)
- [Verification Report](docs/VERIFICATION_REPORT.md)

## Local verification scripts

Use `scripts/verify-local.ps1` on Windows PowerShell or `scripts/verify-local.sh` on macOS/Linux to install dependencies, run backend tests, and build the frontend. A successful run does not replace browser acceptance/security testing. Read `docs/VERIFICATION_REPORT.md` for the checks actually completed in the packaging environment and the remaining limitations.


## Role selection and account approval

The login and registration forms display all four workspace roles: Administrator, Security Analyst, SOC Team Member, and Researcher. The role selected at login is checked against the role stored on the account; it does not grant permissions by itself. Public Researcher registrations are active immediately. Other role requests are stored as inactive until an administrator reviews them and activates the account from **Account governance**. Bootstrap the first administrator using `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`; do not make administrator registration self-service.

## Model artifact integration

The supplied `malware_classifier.pkl`, `feature_schema.json`, `threatlens_pe_random_forest.joblib`, and evaluation CSV/JSON/text artifacts are placed under `backend/ml/artifacts`. The active model path defaults to `ml/artifacts/malware_classifier.pkl`. Inference is deliberately skipped if the extractor does not provide every required feature or the model/schema/runtime checks fail. The schema includes runtime telemetry fields that a static file upload cannot truthfully derive, so do not interpret an unavailable ML result as a benign verdict.


## Demo scan evidence and charts

Every completed scan response includes a separate **Demo threat indicators · display only** panel. It shows inert, synthetic indicator strings and a non-executable code preview for demonstration. This panel is explicitly labelled as simulated, is not extracted from the uploaded file, is not a YARA match, and does not affect the actual verdict or risk score. The dashboard's ten analytics charts use persisted scans when available; before the first scan, they display labelled illustrative demo records so the graph layouts are visible. Demo chart records are never saved as real scan history and must not be used as detection metrics.
