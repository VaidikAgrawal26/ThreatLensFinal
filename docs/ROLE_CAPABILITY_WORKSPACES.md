# ThreatLens AI — 40 Dedicated Role Capability Workspaces

## What changed

The existing application pages and backend routes were preserved. The Role Feature Center now opens a separate route for each capability (`Capability:<role>:<index>`) instead of routing all feature cards to a small set of shared pages. The new workspaces use current scan records and existing API endpoints; they do not create synthetic scan results.

## Administrator (10)
1. **Account governance** — protected administrator API to create an account and list current users.
2. **Service health probe** — refresh `/health` and model readiness independently.
3. **YARA rule inventory** — view current rule inventory and refresh rule metadata.
4. **Ruleset import console** — upload a reviewed ZIP ruleset with source, version and license metadata.
5. **Model readiness inspector** — show model readiness and stored inference outputs, without asserting accuracy.
6. **Global scan monitor** — platform-wide scan totals, high-risk count, unique hashes, search and severity filtering.
7. **Audit event search** — search persisted audit records by actor, action and target.
8. **Platform metric studio** — platform risk and YARA trend visualization from persisted scans.
9. **Notification threshold review** — preview records meeting the default high-risk notification threshold.
10. **Evidence ledger** — select a record, inspect hash/risk/YARA/ML status, and open full evidence.

## SOC Team Member (10)
1. **Severity triage queue** — filter by severity/minimum risk and prioritize by risk score.
2. **Incident creation desk** — create a persistent incident linked to a stored scan.
3. **Scan activity explorer** — search and filter operational scan activity.
4. **Threat event timeline** — visualize stored risk values over scan timestamps and inspect the chronological records.
5. **Response checklist runner** — interactively tick evidence-handling steps; clearly labeled as browser-local checklist state.
6. **Shift handover builder** — export a JSON handover containing high-risk records and identifiers.
7. **SOC operational metrics** — severity counts and a severity distribution chart.
8. **Responder notification review queue** — risk-prioritized high-risk records for review.
9. **Evidence validation desk** — select a record and open the original evidence details.
10. **Duplicate sample grouper** — group scans by exact SHA-256 and list duplicate records.

## Security Analyst (10)
1. **File analysis launchpad** — guided intake checklist with a link to the existing scanner.
2. **Hash and metadata lookup** — search stored records by full/partial hash or filename.
3. **YARA match explorer** — search scans with actual rule hits and open the evidence.
4. **Rule interpretation guide** — practical review checklist and official YARA authoring reference, plus local inventory.
5. **ML inference audit** — show model readiness and records with actual stored ML outputs.
6. **Signal comparison bench** — compare two records' risk, YARA and ML fields side by side.
7. **Risk component breakdown** — chart the stored risk components for a selected record.
8. **Investigation report builder** — download a JSON report for a selected stored scan.
9. **Historical scan comparison** — compare two records and calculate numeric differences where values are numeric.
10. **Indicator filter workspace** — search observed indicators and hashes across stored scans.

## Researcher (10)
1. **Research sample browser** — browse and filter submitted scan records (not a curated malware dataset).
2. **Family hypothesis workbench** — save an explicitly human-authored category/family hypothesis with source and rationale.
3. **ML versus YARA comparison** — compare the presence of the two signals and select records for side-by-side comparison.
4. **Measured feature summary** — summarize only numeric extractor features present in persisted records and export observations.
5. **False-positive review queue** — identify candidate predictions for review and save a human-reviewed annotation.
6. **False-negative review queue** — identify candidate benign predictions for review and save a human-reviewed annotation.
7. **Detection trend explorer** — plot observed risk and YARA hits by stored scan timestamp.
8. **Model explainability audit** — show model readiness and stored outputs while explicitly distinguishing global feature importance from per-sample explanations.
9. **Research dataset export** — export current records as JSON/CSV for offline analysis.
10. **Experiment notebook** — create persistent account-scoped research notes through the existing API.

## Chart functionality

The existing role dashboards and Advanced Analytics page retain the ten configured chart types: line, bar, donut, heatmap, scatter, stacked bar, funnel, histogram, radar and treemap. Those charts remain based on stored scan records. The new capability pages add specific operational charts where useful; they do not replace the existing chart implementation.

## Data and safety boundaries

- Pages requiring protected APIs rely on the existing bearer token and backend role checks. API errors are surfaced rather than silently replaced with sample data.
- Checklist state is explicitly browser-local; it is not presented as a persisted incident action.
- Review labels are analyst-entered annotations, not independent ground truth unless a reviewer establishes that separately.
- ML accuracy/precision/recall are not calculated from unlabeled scans.
- YARA matches are evidence, not a calibrated malware probability; no matches do not establish that a file is safe.
- The frontend production build could not be run in the offline environment because npm dependencies could not be downloaded. JSX syntax was checked with the installed TypeScript transpiler.
