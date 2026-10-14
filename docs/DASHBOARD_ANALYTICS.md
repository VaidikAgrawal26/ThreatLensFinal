# Dashboard Analytics: Definitions and Interpretation

The Overview page provides ten chart types from persisted scan history. The same observed records are interpreted through role-specific headings and explanations. Empty history produces empty/zero-valued visualizations, not fabricated sample data.

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
| Radar | Normalized averages of risk, YARA count, ML score, file-size index and PE indicator | Descriptive normalized profile, not accuracy or a calibrated model explanation |
| Treemap | Stored file-type counts | File type mix based on analyzer classification |

## Role focus
- **Administrator:** platform telemetry and overall scan/risk posture.
- **SOC Team Member:** alert volume, severity and prioritization.
- **Security Analyst:** YARA/model evidence and measured file features.
- **Researcher:** sample/file-type mix and observed static features.

## Metrics deliberately not shown
Accuracy, precision, recall, F1, false-positive rate, false-negative rate and ROC/PR curves require ground-truth labels and a defined evaluation set. Live unlabeled uploads alone cannot support these claims. The current dashboard does not claim to measure these metrics.

## Data freshness
The UI refreshes overview/history periodically and after upload. Values are computed from records stored by this instance; they are not an external live threat feed. Timestamps and file type values depend on the local runtime and parser support.
