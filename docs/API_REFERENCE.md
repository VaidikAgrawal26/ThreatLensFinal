# ThreatLens AI API Reference

Base URL in the default local setup: `http://127.0.0.1:8001`. Interactive OpenAPI docs are at `/docs`.

## Public endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Service name and documentation pointers |
| GET | `/health` | Lightweight API health check; not a full dependency health check |
| POST | `/api/auth/register` | Create Researcher account; password minimum 10 characters |
| POST | `/api/auth/login` | Validate credentials and return signed bearer token + user |

## Authenticated endpoints
Send `Authorization: Bearer <access_token>`.
| Method | Path | Purpose |
|---|---|---|
| GET | `/api/auth/me` | Current authenticated user |
| POST | `/api/auth/logout` | Audit logout event; client must discard token |
| POST | `/api/scans/upload` | Multipart upload and immediate static analysis |
| GET | `/api/scans?limit=100` | Recent scan history (limit is capped) |
| GET | `/api/scans/{scan_id}` | Stored scan result including indicators and YARA evidence |
| GET | `/api/analytics/overview` | Scan totals, risk/severity/verdict counts, daily trend, recent scans |
| GET | `/api/analytics/notifications` | Records meeting configured alert thresholds |
| GET | `/api/analytics/security-report` | JSON summary and limitations |
| GET | `/api/analytics/export.csv` | CSV export of scan history |
| GET | `/api/yara/rules` | Local rule inventory and compile status |
| GET | `/api/model/readiness` | Model artifact/schema readiness, not accuracy |
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
| GET | `/api/admin/users` | List user accounts |
| POST | `/api/admin/users` | Create account with explicit role |
| PATCH | `/api/admin/users/{id}/role` | Assign role |
| PATCH | `/api/admin/users/{id}/status` | Activate/deactivate account |
| GET | `/api/admin/audit` | Review persisted audit events |
| GET | `/api/admin/overview` | User/scan/audit totals |
| POST | `/api/yara/rules` | Upload and compile a reviewed YARA file (multipart `file`) |
| POST | `/api/yara/ruleset` | Import reviewed ZIP pack (multipart `file`, `source`, `version`, `license_name`); every rule is compiled before installation |
| GET | `/api/yara/rulesets` | List imported ruleset manifests/provenance |
| DELETE | `/api/yara/rules/{filename}` | Remove a local root-level YARA file; bundled demo is protected |

## Upload behavior
Allowed extensions: `.exe`, `.dll`, `.sys`, `.scr`, `.ocx`, `.bin`, `.dat`, `.pdf`, `.zip`. This is an extension allowlist, not a file authenticity check. Empty uploads are rejected; configured maximum size defaults to 25 MB. The service does not execute the upload. Scan result fields include hashes, static features, YARA matches/summary, ML availability/output, risk components and a disclaimer.

## Error expectations
- `401`: missing/invalid/expired token.
- `403`: authenticated role lacks permission.
- `409`: duplicate account or duplicate YARA filename.
- `413`: upload/rule file exceeds configured limit.
- `415`: unsupported extension or rule file type.
- `422`: invalid request/schema or YARA compile failure.
- `503`: YARA upload management unavailable because `yara-python` is not installed.

Never place passwords, bearer tokens or sensitive indicators in shared screenshots/reports.
