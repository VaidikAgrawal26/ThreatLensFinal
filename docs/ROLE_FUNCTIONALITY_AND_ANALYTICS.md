# Role Functionality and Analytics Inventory

## Authorization model
Four roles are stored on the server: `administrator`, `soc_member`, `security_analyst`, and `researcher`. Public registration always creates a Researcher. Administrator-only routes manage users/roles/status, view audit events, and add/remove local YARA files. Scan/history/analytics/YARA inventory/model readiness routes require a valid bearer token. The frontend derives its role view from the authenticated user returned by the server; client-side role selection is not used as a permission check.

## Administrator workspace
1. Platform overview and scan analytics — stored scan records.
2. Live scan and scan history — authenticated scan APIs.
3. Notifications — derived from configured scan thresholds.
4. YARA inventory — local rule files, compilation status, rule names/tags/metadata when available.
5. Model readiness — configured artifact/schema presence and parse status.
6. Rule updates — authenticated upload, compile-before-save and removal of local root-level rule files; no upstream auto-download.
7. Audit review — persisted authentication and administrative events.
8. System health — live `/health` response plus model-readiness display.
9. User/role management — create user, assign roles, activate/deactivate; protected by backend RBAC.
10. User/platform overview — API-backed totals are available; no full infrastructure telemetry is claimed.

## SOC Team Member workspace
1. Overview/analytics from real scan history.
2. Live scan and stored history.
3. Notifications from high-risk/YARA signals.
4. Alert triage table sorted by risk/severity.
5. Persistent incident records created from scan evidence, with status updates, assignment to active SOC/analyst/admin users, notes and audit events (not a full ITSM platform).
6. Threat timeline from scan timestamps and risk scores (not cross-source event correlation).
7. Response-playbook checklist for evidence handling (session-local only).
8. Shift-handover high-risk view and CSV export.
9. Evidence detail opens the actual scan record.
10. Exportable scan history for handover.

## Security Analyst workspace
1. Overview and ten scan-derived chart types.
2. Live file scan.
3. Scan history/detail.
4. YARA match evidence in individual scan results when YARA engine/rules are installed.
5. File indicator review (hashes, strings, URLs/IPs, PE metadata where supported).
6. ML readiness and actual model output/availability.
7. Evidence comparison across separate ML/YARA/static channels.
8. Investigation JSON/CSV report.
9. YARA inventory and compile-status inspection.
10. Risk component breakdown with capped additive heuristic explanation.

## Researcher workspace
1. Overview and ten scan-derived chart types.
2. Live scan and historical records.
3. Dataset Explorer of this instance's scans with human-entered ground-truth label/family/source annotations (not an external raw-sample repository).
4. Family Research guidance based on actual rule evidence; no definitive family attribution.
5. Feature Distribution chart from measured stored features.
6. Experiment Notes persisted per authenticated user in the database.
7. CSV research export.
8. Security summary JSON export.
9. Comparison of available ML outputs vs YARA matches.
10. Documentation and reproducibility workflow.

## Chart inventory
The Overview contains line, bar, donut, heatmap, scatter, stacked bar, funnel, histogram, radar and treemap visualizations. Each uses stored records. Role-specific captions explain the intended use. See [Dashboard Analytics](DASHBOARD_ANALYTICS.md) for definitions and limitations. Ground-truth accuracy metrics are intentionally omitted unless an evaluation dataset with labels is provided.

## Remaining boundaries
This is a local prototype, not a production SOC suite. It has no persisted incident assignment/status workflow, no external threat-feed synchronization, no runtime telemetry, no curated malware repository, no SHAP-based explanations, and no tamper-evident audit log. YARA engine and rule collections are separate; the ZIP includes only the illustrative demo rule and the local rule-management interface.
