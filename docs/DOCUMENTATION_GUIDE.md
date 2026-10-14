# ThreatLens AI — Project and Operations Guide

## 1. What the application does
ThreatLens is a local static-triage web application. React/Vite provides the UI; FastAPI accepts authenticated uploads; SQLAlchemy stores scan results in SQLite by default. Uploaded bytes are read and inspected, not intentionally executed. The scanner computes hashes, extracts printable strings and URL/IP indicators, attempts PE parsing, evaluates local YARA rules, and attempts ML inference only when the configured model/schema can be loaded and every required feature is measured.

It is not an endpoint agent, sandbox, runtime behavior monitor, threat-intelligence subscription, or guarantee that a file is safe.

## 2. Architecture

```text
Browser (React + Vite)
  ├─ POST /api/auth/register, /api/auth/login
  ├─ Authorization: Bearer <signed token>
  └─ FastAPI
      ├─ Authentication + role dependencies
      ├─ Static analyzer (hashes, strings, indicators, PE features)
      ├─ Local YARA compiler/matcher
      ├─ Strict model adapter (artifact + exact feature schema)
      ├─ Capped, explainable triage score (not a probability)
      └─ SQLAlchemy: users, audit events, scan history
```

Protected scan, analytics, YARA inventory and model-readiness endpoints require a bearer token. User management and YARA rule add/remove endpoints require `administrator`. Public self-registration always creates a `researcher`; it ignores any submitted role. An administrator must assign elevated roles.

## 3. Windows setup
1. Install Python 3.11+ and Node.js LTS.
2. From the project root, run `py -3.11 -m venv .venv` and `\.venv\Scripts\Activate.ps1`.
3. Install backend dependencies: `cd backend; python -m pip install -r requirements.txt`.
4. Copy `.env.example` to `.env`. Set a unique random `JWT_SECRET`. To bootstrap the first admin, set `BOOTSTRAP_ADMIN_EMAIL` and a strong `BOOTSTRAP_ADMIN_PASSWORD` before first startup. These values are used only to create an admin if that email does not already exist; remove the bootstrap password from the environment after creation.
5. Start the API from `backend`: `python -m uvicorn app.main:app --host 127.0.0.1 --port 8001`.
6. In a second terminal, run `cd frontend`, `npm install`, and `npm run dev`.
7. Open the Vite URL printed in the terminal. The frontend defaults to API `http://127.0.0.1:8001`.
8. Verify `/health` and `/docs`. CORS allows localhost/127.0.0.1 on ports 5173 and 5174 by default; update `CORS_ORIGINS` for a different port.

PowerShell commands should be run in separate terminals for backend and frontend. For Docker, inspect and configure `docker-compose.yml` and the environment before exposing services. Do not use development secrets in deployment.

## 4. First administrator and accounts
Set `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` in `backend/.env` before first start. Sign in through the UI. New self-registered users receive only the Researcher role. In the Administrator workspace, assign `administrator`, `soc_member`, `security_analyst`, or `researcher` as appropriate. Passwords are hashed with PBKDF2-HMAC-SHA256; bearer tokens are signed and expire. Use HTTPS, a high-entropy secret, rate limiting and a reviewed deployment configuration before network exposure.

## 5. Model integration
Place the exact trained scikit-learn pipeline at `backend/ml/artifacts/malware_classifier.pkl` and the `feature_schema.json` generated in the same training run next to it. The schema reader supports `feature_names`, `feature_columns_in_input_order`, `feature_columns`, `features`, or `columns`. For PE samples, the analyzer extracts the known static PE header/section/import fields. Behavioral fields such as registry reads, process events or network telemetry are not fabricated; if the selected model requires them, prediction is marked unavailable with missing feature names. Check `/api/model/readiness` after login. A successful readiness check does not establish predictive quality.

## 6. YARA operations
The bundled `threatlens_demo.yar` is an illustrative integration fixture, not a production signature set. In the Administrator → Rule Updates workflow, upload a reviewed `.yar`/`.yara` file; it is compiled before it is written. Remove local rules through the same page. Files are not automatically downloaded from upstream repositories. Record provenance, source commit/version and license alongside the rules. The rule inventory reports compilation errors and rule metadata where the installed engine exposes it.

## 7. Triage and scoring
Risk score is a capped additive heuristic from entropy, suspicious API indicators, embedded network indicators, unique YARA rules and an available ML result. It is not calibrated probability and signals may be correlated. Read the component breakdown and raw evidence. A no-match YARA result, low score or Benign ML label is not proof of safety.

## 8. Storage, privacy and maintenance
- SQLite data lives in `backend/data/threatlens.db` by default.
- Uploaded bytes are analyzed in memory and are not intentionally stored as sample files by this service; scan evidence and extracted strings are stored in the scan JSON result.
- Review extracted strings and indicators before sharing reports; they may contain sensitive data.
- Define retention, backups, file-size limits, log retention and access controls before operational use.
- Audit events record registration/login and administrative user changes. They are ordinary database records, not tamper-evident or externally immutable logs.

## 9. Documentation map
- [API Reference](API_REFERENCE.md)
- [Architecture and Threat Model](ARCHITECTURE.md)
- [ML Model Integration](ML_MODEL_INTEGRATION.md)
- [Dashboard Analytics](DASHBOARD_ANALYTICS.md)
- [YARA Library and Mapping](YARA_LIBRARY_AND_MAPPING.md)
- [Testing Guide](TESTING.md)
- [Role Functionality Inventory](ROLE_FUNCTIONALITY_AND_ANALYTICS.md)
- [Verification Report](VERIFICATION_REPORT.md)
