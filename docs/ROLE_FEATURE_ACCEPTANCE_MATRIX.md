# Role feature acceptance matrix

## Counting rule

The ten capabilities below are distinct role outcomes. Shared platform features such as sign-in, navigation and profile management are foundations, not capabilities counted for each role. Shared stored scan records may supply evidence to several roles, but each role acts on that evidence for a different use case. Server-side permissions remain authoritative.

## Administrator - platform governance

| # | Capability | Main implementation |
|---:|---|---|
| 1 | Govern account creation, roles and status | `Administration`; `/api/admin/users` endpoints |
| 2 | Check API/service health | `System Health`; `GET /health` |
| 3 | Inspect installed YARA files and compile state | `YARA Library`; `GET /api/yara/rules` |
| 4 | Import a versioned ruleset after validation | `Rule Updates`; `POST /api/yara/ruleset` |
| 5 | Review model/schema release readiness and saved evaluation provenance | `Model Readiness`; `/api/model/readiness`, `/api/model/evaluation` |
| 6 | Monitor platform-wide scan records | `Scan History`; scan APIs |
| 7 | Search the security audit trail | `Audit Review`; `GET /api/admin/audit` |
| 8 | Review platform scan analytics | `Advanced Analytics`; analytics APIs |
| 9 | Review notification-threshold impact | `Notifications`; threshold-qualified stored scan records |
| 10 | Review account, scan and audit governance totals | Governance coverage summary; `GET /api/admin/overview` |

## SOC Team Member - operational response

| # | Capability | Main implementation |
|---:|---|---|
| 1 | Review operational threat posture for the shift | SOC posture; severity/risk summaries |
| 2 | Create, assign and update an incident | `Incident Queue`; `/api/incidents` |
| 3 | Prioritize alerts by severity/risk | `Alert Triage`; stored scan records |
| 4 | Search scan activity by file/hash/severity | Activity search; stored scan records |
| 5 | Inspect the time-ordered threat timeline | `Threat Timeline`; stored scan timestamps |
| 6 | Work an evidence-handling response checklist | `Response Playbooks`; local checklist state |
| 7 | Export evidence for shift handover | `Shift Handover`; JSON/CSV export |
| 8 | Review SOC queue and workload metrics | SOC analytics workspace; loaded scan records |
| 9 | Review the responder notification queue | `Notifications`; threshold-qualified stored records |
| 10 | Group duplicate records by exact SHA-256 | SOC duplicate grouper; loaded scan records |

## Security Analyst - file investigation

| # | Capability | Main implementation |
|---:|---|---|
| 1 | Submit an authorized sample for static analysis | `Live Scan`; `POST /api/scans/upload` |
| 2 | Locate a sample by hash or filename | `File Indicators`; stored scan records |
| 3 | Inspect actual YARA match evidence | `Rule Match Explorer`; scan detail response |
| 4 | Interpret YARA rule metadata and compilation context | YARA library and rule guide |
| 5 | Audit per-scan model availability and output | `ML Explanation`; model readiness + scan records |
| 6 | Compare static, YARA and ML signals side by side | `Evidence Comparison` |
| 7 | Explain heuristic risk-score components | Scan detail risk breakdown |
| 8 | Export a selected-scan investigation report | `Investigation Report` |
| 9 | Diff two historical scan records | Analyst history comparison |
| 10 | Filter stored indicators of compromise | IOC filter workspace |

## Researcher - evaluation and reproducibility

| # | Capability | Main implementation |
|---:|---|---|
| 1 | Browse samples/scan records stored in this instance | `Dataset Explorer` |
| 2 | Record independently sourced benign/malware labels | `/api/research/annotations` |
| 3 | Record family/category hypotheses with rationale | `Family Research`; research annotations |
| 4 | Summarize measured feature distributions | `Feature Distribution` |
| 5 | Curate suspected false-positive review candidates | False-positive review workspace |
| 6 | Curate suspected false-negative review candidates | False-negative review workspace |
| 7 | Explore scan-derived trends without claiming model accuracy | Research trend workspace; stored scan records |
| 8 | Inspect training evaluation artifacts and consistency warnings | Model explainability/evaluation review; `/api/model/evaluation` |
| 9 | Export scan records and reviewer annotations for offline research | Research export; research/analytics APIs |
| 10 | Save per-user reproducibility notes | `Experiment Notes`; `/api/research/notes` |

## Authorization acceptance

- Login requires the selected workspace to match the account role stored in the database.
- Researcher registration activates immediately; privileged role requests stay pending until an administrator activates them.
- The SOC role cannot upload files. Administrator, Security Analyst and Researcher may submit scans under the current policy.
- Account, role, status, audit and YARA mutation endpoints require an administrator token.
- Incident endpoints require an administrator, Security Analyst or SOC token.
- Research annotations and notes require a researcher, analyst or administrator token. Notes are returned only for their owner.
- Model readiness/evaluation, scan, history, analytics and YARA inventory APIs require authentication.

## Limitations to keep visible

- A shared API or scan record does not imply that every role has the same action permissions.
- The response playbook checklist is browser-local; it is not a persisted incident.
- Model metrics are saved training artifacts and not accuracy on live uploaded files.
- The supplied model needs runtime fields absent from static file analysis; inference may be unavailable.
- Research labels are reviewer inputs, not automatically verified ground truth.
- See [Implementation Plan](IMPLEMENTATION_PLAN.md) and [Model Validation Review](MODEL_VALIDATION_REVIEW.md) for release gates and unresolved training validation.
