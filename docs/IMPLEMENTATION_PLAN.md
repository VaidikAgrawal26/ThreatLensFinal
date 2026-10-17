# ThreatLens AI implementation plan

## Product goal

Build a secure, evidence-led platform for static malware triage. Analysts submit an authorized file; the API computes hashes and supported static indicators, evaluates local YARA rules, attempts model inference only when the required input schema is available, persists the result, and exposes role-specific review workflows. The scanner does not execute files and is not a sandbox or a production malware-detection guarantee.

## Implementation status

The repository now contains the application implementation and local/production deployment definitions. External services, a real deployment, operational runbooks, and release acceptance evidence still require operator setup and review; their presence is not implied by the code.

| Workstream | Implemented in this repository | Remaining before operational use |
|---|---|---|
| Web client | React 18/Vite role workspaces, authenticated API client, scan review, analytics, YARA, incident and research workflows | Complete browser/accessibility acceptance review and production build on the target host |
| API | FastAPI authentication, role checks, bounded uploads, static scan, YARA, analytics, incidents, research, administration, audit and model readiness routes | Run role/action acceptance and security review against the release configuration |
| Storage | SQLAlchemy entities, Alembic migrations, local SQLite support and private PostgreSQL Compose service | Establish production backup/restore, retention, and restore drills |
| File analysis | Hashes, measured static indicators, optional PE parsing, local YARA, heuristic risk and explicit model-unavailable states | Validate limits and evidence quality against an authorized corpus; dynamic analysis remains a separate service if needed |
| ML | Existing artifacts and schema are wired to conditional inference; incompatible or unavailable inputs do not produce a prediction | Attach the user's intended trained artifact/schema, reconcile provenance, then evaluate on a deduplicated independent holdout |
| Operations | Development Compose stack, production Compose overlay, non-root containers, Caddy HTTPS proxy, health/readiness checks and production configuration guards | Deploy with operator-managed secrets, DNS/firewall, monitoring, external rate limiting, backup/retention policy and incident procedures |
| External services | The architecture brief names VirusTotal, threat feeds, email and SIEM/SOAR as possible integrations | Add only after credentials, data-handling policy, licensing and failure behavior are specified |

## Delivery phases

### Phase 1 - Scope, roles and data contracts

- Freeze the static-analysis boundary and approved file types, size limits, and retention rules.
- Define the four role grants below and make the API the authority for every permission check.
- Establish stable scan, YARA, model, incident and research annotation response schemas.
- Keep provenance on evidence: source file, hash, timestamp, rule version, model/schema version, and whether a value was measured or unavailable.

### Phase 2 - Authentication and access control

- Keep login role selection as a convenience check against the server-stored role; it never grants privileges.
- Let each authenticated user update their own display name and email; audit the change and keep role changes administrator-only.
- Keep researcher self-registration active and privileged role requests pending administrator activation.
- Require a securely bootstrapped administrator; hash passwords; expire signed access tokens; audit account changes and sign-in events.
- Enforce role permissions on API routes and test both allowed and denied requests.

### Phase 3 - Static intake and evidence pipeline

- Validate upload size and type; compute SHA-256 and MD5; detect file type; collect strings, URLs/IPs and supported PE fields.
- Run only locally installed YARA files and record compile/evaluation status and rule provenance.
- Call the ML service only when all required schema fields are genuinely observed. Do not replace unknown behavior with zeroes.
- Synthesize a clearly labeled heuristic triage score from available evidence; preserve each component and its explanation.
- Persist the complete scan record and return a structured report without executing the sample.

### Phase 4 - Four non-overlapping role workspaces

The role feature center should count the following ten workflow outcomes for each role. Common shell features (sign-in, profile identity, and navigation) are platform foundations, not duplicate role capabilities. Shared scan records are data sources; the role's action and resulting output remain distinct.

#### Administrator - platform governance

1. Provision an account.
2. Assign or change an account role.
3. Activate or suspend an account.
4. Search the security audit trail.
5. Check API/service health.
6. Review model/schema release readiness.
7. Inspect the installed YARA inventory and compile state.
8. Import a versioned, licensed ruleset after validation.
9. Monitor platform-wide scan volume and unique file hashes.
10. Review governance metrics and notification-threshold impact.

#### SOC Team Member - operational response

1. Prioritize alerts by severity and risk.
2. Open an incident from a scan.
3. Assign an incident to an eligible responder.
4. Move an incident through its operational status lifecycle.
5. Review scan activity using filename/hash/severity filters.
6. Inspect the time-ordered threat timeline.
7. Work a response evidence checklist.
8. Export a shift handover containing real stored evidence.
9. Group duplicate records by exact SHA-256.
10. Review the responder notification queue.

#### Security Analyst - file investigation

1. Perform authorized static file intake.
2. Search a sample by hash or filename.
3. Inspect actual YARA match evidence.
4. Interpret rule metadata and compilation context.
5. Audit per-scan model availability and output.
6. Compare static, YARA and ML evidence channels.
7. Explain heuristic risk-score components.
8. Export a selected-scan investigation report.
9. Diff two historical scan records.
10. Filter stored indicators of compromise (IOCs).

#### Researcher - evaluation and reproducibility

1. Browse the locally stored sample/scan set.
2. Record independently sourced benign/malware labels.
3. Record family/category hypotheses with rationale.
4. Summarize only measured feature distributions.
5. Curate suspected false-positive review candidates.
6. Curate suspected false-negative review candidates.
7. Compare model and YARA signal coverage without calling it accuracy.
8. Inspect saved model evaluation artifacts and their consistency warnings.
9. Export scan and annotation data for offline research.
10. Save per-user experiment notes for reproducibility.

### Phase 5 - Analytics, alerts and reporting

- Keep dashboards descriptive: counts, severity, trend and evidence composition.
- Call notifications actionable review signals, not confirmed infections.
- Calculate accuracy/precision/recall/F1/ROC-AUC only from an explicitly labeled independent evaluation set.
- Provide machine-readable JSON/CSV exports and a human-readable investigation summary.

### Phase 6 - Validation, release and deployment

- Verify authentication, role permissions, uploads, YARA compile failures, model mismatch, persistence and exports.
- Validate duplicate-sample handling and database migration/backup/restore.
- Build and run the Docker Compose stack with deployment secrets supplied outside source control.
- Before external use, configure the supplied TLS proxy, add edge rate limiting and structured monitoring, define retention and protected backups, review dependencies, and establish incident response procedures.
- Integrate external feeds only after credentials, legal terms, privacy boundaries, outage handling and audit requirements are set.

## Release acceptance gates

- Each role can log in only with its assigned server-side role and receives exactly its approved permissions.
- There are ten named, role-specific workflows per role; their outcomes are not presented as interchangeable capabilities.
- A successful scan records hash, type, measured indicators, YARA evaluation state, model availability, risk components and timestamp.
- Missing training-schema values may be imputed only by the selected model’s fitted transformers; scans must mark partial coverage and distinguish imputed inputs from file evidence.
- Every alert/report links to stored evidence and clearly labels heuristic or simulated content.
- API denial tests prove that unauthorized roles cannot reach protected endpoints.
- Model metrics are traceable to a documented dataset split, class supports, preprocessing pipeline and model/schema pair.
- The final deployment has an operator-owned secrets, backups, retention, TLS and monitoring configuration.

## Current boundaries

The production YARA rules directory is empty by default; only reviewed rules installed by an administrator are evaluated. The final configured model is the user-supplied Random Forest with a 72-feature schema. Its fitted imputers allow PE uploads to receive partial static estimates despite unavailable runtime telemetry; the app marks coverage and imputation explicitly. Its 99.10% random-split result is not a live accuracy guarantee and requires independent holdout validation. See [Model Validation Review](MODEL_VALIDATION_REVIEW.md).
