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
4. Create/update the local database schema from `backend`:
   ```powershell
   alembic upgrade head
   ```
5. Start the API from `backend`:
   ```powershell
      python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
   ```
6. In a second PowerShell terminal, from `frontend`:
   ```powershell
   npm install
   npm run dev
   ```
7. Open the URL printed by Vite. Default API: `http://127.0.0.1:8000`; API docs: `http://127.0.0.1:8000/docs`.

If Vite chooses a port other than 5173/5174, add the exact origin to `CORS_ORIGINS` in `backend/.env` and restart the backend. The frontend API URL can be overridden in `frontend/.env.local` using `VITE_API_URL`.

## Docker option

Copy `.env.example` to `.env` for local Docker use, then run `docker compose up --build` from the project root. This starts PostgreSQL, the API on port 8000, and the frontend on port 5173. The example values are development-only. For deployment, create a private environment file with a unique JWT secret, strong database/admin passwords, domain and explicit origins, then use `docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile production --env-file .env.production up --build`. The production overlay keeps database/API ports private and uses Caddy for HTTPS. Configure DNS and allow inbound ports 80/443 at the host firewall.

For a manually managed Render demo deployment, start with [the Render deployment guide](docs/RENDER_DEPLOYMENT.md) and the root [render.yaml](render.yaml) Blueprint. The Blueprint uses a temporary free Postgres plan for demonstration; select a persistent paid database plan if scan history must last beyond the free database's expiration window.

## Authentication and roles
- Signup displays all four roles: Administrator, Security Analyst, SOC Team Member, and Researcher. The role is stored server-side and the login selection must match the saved role.
- Researcher signups activate immediately; Administrator, Security Analyst, and SOC Team Member signups remain pending until an administrator activates them. Bootstrap the first administrator using the environment variables above.
- Only administrators can change roles/status, view audit events, manage accounts, and add/remove local YARA rule files.
- File uploads are allowed for Administrator, Security Analyst, and Researcher roles. SOC Team Members can monitor scan history, alerts and incidents but cannot upload files. Scan, history, analytics, YARA inventory and model-readiness APIs require a signed bearer token.
- Production mode fails closed on the development JWT secret and SQLite. Use PostgreSQL migrations, strong secrets, HTTPS, retention policies, protected backups, rate limiting at the edge, and separately controlled audit-log storage before handling operational samples.

## ML artifact
The active model is the user-supplied Random Forest at `backend/ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/`, paired with its 72-column `feature_schema.json`, metrics, report and feature-importance file. PE header/section/import features are extracted when `pefile` is installed. The model pipeline's fitted imputers fill missing inputs; scans explicitly mark partial coverage and missing runtime fields. See [ML Model Integration](docs/ML_MODEL_INTEGRATION.md).

The active Random Forest requires the pinned scikit-learn 1.9.1 runtime. It produces a static-file estimate by using its fitted median/mode imputers for missing telemetry; the app labels these predictions as partial and displays input coverage. This adaptation makes the existing model callable for PE uploads, but its 99.10% reported holdout metrics do not establish live-upload accuracy.

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
- [Implementation Plan and Role Acceptance Matrix](docs/IMPLEMENTATION_PLAN.md)
- [Role Feature Acceptance Matrix](docs/ROLE_FEATURE_ACCEPTANCE_MATRIX.md)
- [Model Validation Review](docs/MODEL_VALIDATION_REVIEW.md)
- [YARA Library and Mapping](docs/YARA_LIBRARY_AND_MAPPING.md)
- [Verification Report](docs/VERIFICATION_REPORT.md)

## Local verification scripts

Use `scripts/verify-local.ps1` on Windows PowerShell or `scripts/verify-local.sh` on macOS/Linux to install dependencies, run backend tests, and build the frontend. A successful run does not replace browser acceptance/security testing. Read `docs/VERIFICATION_REPORT.md` for the checks actually completed in the packaging environment and the remaining limitations.


## Role selection and account approval

The login and registration forms display all four workspace roles: Administrator, Security Analyst, SOC Team Member, and Researcher. The role selected at login is checked against the role stored on the account; it does not grant permissions by itself. Public Researcher registrations are active immediately. Other role requests are stored as inactive until an administrator reviews them and activates the account from **Account governance**. Bootstrap the first administrator using `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`; do not make administrator registration self-service.

## Model artifact integration

The active model path defaults to `ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/threatlens_pe_random_forest.joblib`, with its paired schema in the same directory. Valid PE uploads receive a Random Forest estimate when core static fields are extractable; the saved pipeline imputes fields the static scanner cannot observe and each result reports coverage and missing runtime inputs. Treat partial estimates as triage signals, not observed behavior, proof of malware, or proof of safety.


## Demo scan evidence and charts

Every completed scan response includes a separate **Demo threat indicators · display only** panel. It shows inert, synthetic indicator strings and a non-executable code preview for demonstration. This panel is explicitly labelled as simulated, is not extracted from the uploaded file, is not a YARA match, and does not affect the actual verdict or risk score. The dashboard's ten analytics charts use persisted scans when available; before the first scan, they display labelled illustrative demo records so the graph layouts are visible. Demo chart records are never saved as real scan history and must not be used as detection metrics.
