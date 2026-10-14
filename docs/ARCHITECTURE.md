# Architecture, Data Flow, and Threat Model

## Components
1. **React/Vite browser UI** — landing page, authentication, four role-specific navigation sets, upload form, history, analytics, YARA inventory and role workflows.
2. **FastAPI** — request validation, bearer authentication, server-side role dependencies, scan/analytics/admin/YARA/model routes.
3. **Static analyzer** — SHA-256/MD5, entropy, printable strings, URLs/IPs, PE header/section/import extraction where `pefile` is available.
4. **YARA adapter** — recursively finds local `.yar`/`.yara` files, compiles them, applies each compiled file to the bytes with a timeout, and records matches/errors.
5. **ML adapter** — loads a trusted joblib artifact only when the matching schema exists; checks missing fields and model feature ordering before inference.
6. **Risk layer** — capped heuristic score with separate component values; it is not a calibrated probability.
7. **SQLite/SQLAlchemy** — users, scan JSON/history, audit events.

## Request path
```text
Login → signed bearer token → protected API request
Upload → size/extension checks → hash/indicator extraction → PE features
      → local YARA scan → compatible ML inference or explicit unavailable result
      → risk components → database row → UI result/history/analytics
```

## Security controls present
- PBKDF2-HMAC-SHA256 password hashes with per-password salt.
- Signed HMAC-SHA256 bearer tokens with expiry.
- Self-registration cannot assign privileged roles.
- Protected data routes require a valid token; account and YARA rule mutations require Administrator.
- Uploaded files are not intentionally executed; upload size and extension are constrained.
- YARA files are compiled before being added; path traversal and duplicate root-level names are rejected.
- Audit events record selected authentication/admin events.

## Residual risks and required production controls
- Use a unique, random `JWT_SECRET`, HTTPS, rate limiting, secure deployment secrets and account lockout/abuse monitoring.
- The audit table is not tamper-evident. Forward security logs to a separately controlled system for real incident response.
- Uploaded data may contain sensitive strings; define retention, authorization and redaction policies.
- No isolated malware sandbox, process telemetry, runtime monitoring, antivirus engine or external reputation lookup is bundled.
- A YARA rule can be expensive or erroneous; review sources and test timeouts/performance before deploying a large ruleset.
- Joblib/pickle files can execute code when deserialized. Load only trusted artifacts.
- SQLite is intended for local/small-scale use. Use migrations, backups and a managed database before multi-user production deployment.
- Browser-local notes are not server-persisted. Role workflows are not a full ticketing/incident assignment system.
