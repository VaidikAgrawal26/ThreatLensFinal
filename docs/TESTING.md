# ThreatLens AI Test Guide

## Automated backend tests
From `backend` with requirements installed:
```powershell
python -m compileall -q app tests
python -m pytest -q
```
Tests cover health, auth/registration policy, protected endpoints, upload/history round-trip, role enforcement, admin user/role management, audit records, ML schema parsing/missing features, risk component reporting and safe static analysis behavior. YARA/PE-specific behavior requires `yara-python` and `pefile` to be installed.

## Manual startup
1. Copy `backend/.env.example` to `backend/.env`.
2. Set a unique high-entropy `JWT_SECRET`.
3. Set `BOOTSTRAP_ADMIN_EMAIL` and a unique `BOOTSTRAP_ADMIN_PASSWORD` for first startup only, then remove the password from the environment.
4. Run the backend from `backend`: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8001`.
5. Run the frontend from `frontend`: `npm install`, then `npm run dev`.
6. Sign in as admin; register a second account and confirm it receives Researcher role. Assign its role from Administration and verify the backend denies unauthorized admin requests.

## Authentication and authorization
- Anonymous `GET /api/scans` must return 401.
- Authenticated Researcher `GET /api/scans` must return 200.
- Researcher `GET /api/admin/users` must return 403.
- Administrator can list/create users, change role/status, review audit and manage YARA rules.
- Registering with a submitted `role=administrator` must still return `researcher`.
- Tampered/expired bearer tokens must return 401.

## Upload and analyzer tests
1. Upload a harmless supported `.bin` or `.dat` fixture; confirm MD5/SHA-256 and scan ID.
2. Upload an unsupported extension; expect 415.
3. Upload an empty file; expect 400.
4. Upload a file larger than `MAX_UPLOAD_MB`; expect 413.
5. Use benign files only unless operating in an isolated malware lab. Never execute samples.

## Incident and research workflows
- As SOC/analyst/admin, create an incident from a scan, assign an active eligible user, move it through open/investigating/resolved/false-positive, and confirm changes persist after refresh.
- As Researcher/analyst/admin, annotate a scan with a human-reviewed label, source, family hypothesis and evidence notes. Do not call unknown labels ground truth.
- Save a research note and confirm it is visible to the same account after re-login; another account should not see that user’s private notes.

## YARA tests
1. Install `yara-python` from `requirements.txt`.
2. Upload a harmless test fixture containing at least two of `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread`; expected demo rule: `ThreatLens_Demo_Suspicious_API_Strings`.
3. Scan a benign fixture without these strings; expect no match for this demo rule.
4. Open YARA Library and verify local files, compile status, rule count, names/tags/meta and any errors.
5. As Administrator, upload a valid `.yar` rule and confirm it appears; upload invalid syntax and expect 422; try duplicate names and expect 409; remove a non-demo local rule and confirm it disappears.
6. Record source, license, version/commit, date and fixture hashes. The bundled demo rule is illustrative only.

## ML integration tests
1. Place the actual trusted `malware_classifier.pkl` and its paired `feature_schema.json` in `backend/ml/artifacts/`.
2. Authenticate and request `/api/model/readiness`.
3. Confirm the schema feature count and order. If the model requires features not extractable from a static file, inference must remain unavailable and name missing fields.
4. Test on labeled held-out examples from the same feature contract. Review false positives and false negatives.
5. Verify model and schema/library versions. Do not call a model score a calibrated probability unless calibration was evaluated.

## Frontend build and end-to-end checks
```powershell
cd frontend
npm install
npm run build
```
Then run `npm run dev`, sign in, scan a harmless fixture, open detail/history, refresh analytics, export CSV, verify role navigation, and test responsive layout. In this packaging environment a full Vite production build could not be run because npm dependencies were unavailable; JSX syntax was checked with the globally installed TypeScript transpiler.

## Common errors
- 401: sign in again; token missing/expired.
- 403: current role lacks permission; do not bypass backend checks.
- Connection refused: check Uvicorn port and `VITE_API_URL`.
- CORS: add exact Vite origin to `CORS_ORIGINS` and restart API.
- YARA engine unavailable: install requirements in the active venv.
- Model unavailable: check artifact/schema paths, schema keys, exact feature names/order and sklearn version.
