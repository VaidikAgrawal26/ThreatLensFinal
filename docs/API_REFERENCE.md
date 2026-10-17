# ThreatLens AI API Reference

Base URL in the default local setup: `http://127.0.0.1:8000`. Interactive OpenAPI docs are available at `/docs` in development and are disabled in production mode.

## Public endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service name and documentation pointers |
| GET | `/health` | Lightweight API health check; not a full dependency health check |
| POST | `/api/auth/register` | Create Researcher account or submit a privileged role request; password minimum 10 characters |
| POST | `/api/auth/login` | Validate credentials and return signed bearer token + user |

## Authenticated endpoints
Send `Authorization: Bearer <access_token>`.
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/auth/me` | Current authenticated user |
| PATCH | `/api/auth/profile` | Update current user's display name and email; records an audit event |
| POST | `/api/auth/logout` | Revoke current bearer token and record the logout event |
| POST | `/api/scans/upload` | Multipart upload and immediate static analysis |
| GET | `/api/scans?limit=100&offset=0` | Authenticated scan history (limit and offset are bounded) |
| GET | `/api/scans/{scan_id}` | Stored scan result including indicators and YARA evidence |
| GET | `/api/analytics/overview` | Scan totals, risk/severity/verdict counts, daily trend, recent scans |
| GET | `/api/analytics/notifications` | Records meeting configured alert thresholds |
| GET | `/api/analytics/security-report` | Detailed report: evidence coverage, distributions, priority scan findings, methodology and limitations |
| GET | `/api/analytics/security-report.csv` | CSV export of the detailed report's bounded scan window |
| GET | `/api/analytics/export.csv` | CSV export of scan history |
| GET | `/api/yara/rules` | Local rule inventory and compile status |
| GET | `/api/model/readiness` | Model artifact/schema readiness, not accuracy |
| GET | `/api/model/evaluation` | Saved offline training artifacts and explicit consistency notes (not live scan accuracy) |
| GET/POST | `/api/incidents` | List/create persistent incidents from scan records (SOC/analyst/admin) |
| PATCH | `/api/incidents/{id}` | Update incident status, assignee and notes |
| GET | `/api/incidents/assignees` | Active eligible incident assignees |
| GET/POST | `/api/research/annotations` | View/save human-entered scan labels and family/source notes |
| DELETE | `/api/research/annotations/{id}` | Remove an annotation you created or as administrator |
| GET/POST | `/api/research/notes` | List/create persistent private research notes for the current user |
| DELETE | `/api/research/notes/{id}` | Remove your own research note or as administrator |
| GET | `/api/research/summary` | Exploratory labeled prediction counts with limitations; not a substitute for holdout evaluation |

## Administrator-only endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/admin/users?limit=500&offset=0` | Paginated user-account list |
| POST | `/api/admin/users` | Create account with explicit role |
| PATCH | `/api/admin/users/{id}/role` | Assign role |
| PATCH | `/api/admin/users/{id}/status` | Activate/deactivate account |
| GET | `/api/admin/audit?limit=500&offset=0&action=...&actor_email=...` | Search paginated audit events |
| GET | `/api/admin/overview` | User/scan/audit totals |
| POST | `/api/yara/rules` | Upload and compile a reviewed YARA file (multipart `file`) |
| POST | `/api/yara/ruleset` | Import reviewed ZIP pack (multipart `file`, `source`, `version`, `license_name`); every rule is compiled before installation |
| GET | `/api/yara/rulesets` | List imported ruleset manifests/provenance |
| DELETE | `/api/yara/rules/{filename}` | Remove a local root-level YARA file; bundled demo is protected |

## Upload behavior
Allowed extensions: `.exe`, `.dll`, `.sys`, `.scr`, `.ocx`, `.bin`, `.dat`, `.pdf`, `.zip`. Obvious PE, PDF and ZIP extension/signature mismatches are rejected; `.bin` and `.dat` remain generic byte containers. Empty uploads are rejected; configured maximum size defaults to 25 MB. Analysis runs off the ASGI event loop. Submitted bytes are not retained; only the scan evidence record is persisted. The service does not execute the upload. Scan result fields include hashes, measured static features, YARA matches/summary, explicit ML availability, risk components and a disclaimer.

## Error expectations
- `401`: missing/invalid/expired token.
- `403`: authenticated role lacks permission.
- `429`: sign-in account reached the current failed-attempt threshold; response includes `Retry-After`.
- `409`: duplicate account or duplicate YARA filename.
- `413`: upload/rule file exceeds configured limit.
- `415`: unsupported extension or rule file type.
- `422`: invalid request/schema or YARA compile failure.
- `503`: YARA upload management unavailable because `yara-python` is not installed.

Never place passwords, bearer tokens or sensitive indicators in shared screenshots/reports.

## Deployment and data handling

- Apply the Alembic migration before starting the API in both local and production modes. Production requires PostgreSQL; local development can use SQLite.
- Production mode requires an explicit JWT secret, CORS origin and trusted host. The production Compose overlay terminates HTTPS at Caddy and does not publish database or API ports.
- `GET /health` is a liveness endpoint; `GET /ready` checks database connectivity and returns 503 when the database is unavailable.
- Every API response includes an `X-Request-ID`; unhandled errors return a generic message with that identifier, while the server logs the exception.
- Static uploads do not provide registry, process, or runtime network telemetry. The active Random Forest applies its fitted median/mode imputers to missing fields and marks such results partial, exposing input coverage and missing runtime fields; this is a triage estimate, not observed behavior. Its encoder also reports categorical values outside the training vocabulary.
