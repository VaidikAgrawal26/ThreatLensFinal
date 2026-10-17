# Dashboard Analytics: Definitions and Interpretation

The Overview page provides a compact set of role-focused charts and three shortcuts for the current user's main work. **Advanced Analytics** contains the full ten-chart library. When there are no saved scans, the analytics area shows an empty state. Charts render only from persisted scan records.

| Chart | Input | Interpretation / limitation |
|---|---|---|
| Line time series | Counts by scan date | Volume trend; not incident rate without a known denominator |
| Bar chart | Stored verdict counts | Current result distribution |
| Donut | Low/medium/high/critical scan counts | Composition of current scan records |
| Heatmap | Stored scan timestamps by weekday/hour | Upload activity pattern, not attack activity |
| Scatter | File size bytes vs risk score | Descriptive association, not causation |
| Stacked bar | Severity counts by date | Severity mix over recorded days |
| Funnel | All / medium+ / high+ / critical record counts | Nested severity thresholds, not process conversion |
| Histogram | Risk score in fixed bins | Score distribution, not probability calibration |
| Radar | Normalized descriptive averages of evidence and measured features | Descriptive profile, not accuracy or a calibrated model explanation |
| Treemap | Stored file-type counts | File type mix based on analyzer classification |

## Role focus
- **Administrator:** blue platform-governance theme, account/audit metrics, service health, ruleset control and platform telemetry.
- **SOC Team Member:** amber response theme, notification and incident queue, critical scans, duplicate hashes and priority trends.
- **Security Analyst:** violet investigation theme, YARA coverage, model availability, IOC-bearing files and evidence comparisons.
- **Researcher:** green research theme, stored samples, annotation coverage and measured-feature trends.

## Detailed analysis report

The dashboard and Advanced Analytics can generate a self-contained HTML report or export the same detailed report data as JSON. The report includes its scan window, risk and verdict distributions, measured evidence coverage, priority findings with hashes/risk components/YARA/indicator evidence, daily scan volume, methodology, and limitations. CSV export provides the bounded scan records. The report explicitly avoids treating heuristic risk as a probability or unavailable ML output as benign.

## Metrics deliberately not shown
Accuracy, precision, recall, F1, false-positive rate, false-negative rate and ROC/PR curves require ground-truth labels and a defined evaluation set. Live unlabeled uploads alone cannot support these claims. The current dashboard does not claim to measure these metrics.

## Data freshness
The UI refreshes overview/history periodically and after upload. Values are computed from records stored by this instance; they are not an external live threat feed. Timestamps and file type values depend on the local runtime and parser support.
