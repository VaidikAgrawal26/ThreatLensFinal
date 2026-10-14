# Role Feature Acceptance Matrix — additive integration

This addition preserves the existing pages and APIs and adds **Role Feature Center** to each authenticated workspace. The center gives direct navigation to ten role-specific capabilities and lists the ten chart types already available in Overview / Advanced Analytics.

## Administrator — 10 capabilities
1. User and role management — `Administration`
2. Platform health — `System Health`
3. YARA library management — `YARA Library`
4. Ruleset imports and updates — `Rule Updates`
5. Model artifact readiness — `Model Readiness`
6. Global scan monitoring — `Scan History`
7. Audit event review — `Audit Review`
8. Platform analytics — `Advanced Analytics`
9. Threat notifications — `Notifications`
10. Static evidence inspection — `Live Scan`

## SOC Team Member — 10 capabilities
1. Threat overview — `Overview`
2. Live alert triage — `Alert Triage`
3. Incident queue, assignment and status — `Incident Queue`
4. Scan activity — `Scan History`
5. Threat timeline — `Threat Timeline`
6. Response checklist — `Response Playbooks`
7. Shift handover — `Shift Handover`
8. Operational analytics — `Advanced Analytics`
9. Notifications — `Notifications`
10. Evidence detail — `Live Scan`

## Security Analyst — 10 capabilities
1. Static file scanner — `Live Scan`
2. Hash and metadata review — `File Indicators`
3. YARA match explorer — `Rule Match Explorer`
4. Rule explanations and library references — `YARA Library`
5. ML assessment availability/output — `ML Explanation`
6. Evidence comparison — `Evidence Comparison`
7. Risk component review — scan detail in `Live Scan`
8. Investigation reporting — `Investigation Report`
9. Historical comparison — `Scan History`
10. Investigation analytics — `Advanced Analytics`

## Researcher — 10 capabilities
1. Sample record explorer and label annotations — `Dataset Explorer`
2. Category/family research notes — `Family Research`
3. Model-vs-YARA comparison — `Evidence Comparison`
4. Feature distribution — `Feature Distribution`
5. False-positive review support — `Dataset Explorer`
6. False-negative review support — `Dataset Explorer`
7. Detection trend analysis — `Advanced Analytics`
8. ML output/availability review — `ML Explanation`
9. Research export — `Export Research`
10. Reproducibility notes — `Experiment Notes`

## Ten chart types
1. Line trend
2. Bar comparison
3. Donut composition
4. Weekday/hour heatmap
5. Scatter relationship
6. Stacked bar over time
7. Triage funnel
8. Histogram
9. Radar profile
10. Treemap

Charts use the loaded scan records. The role feature center is an additive navigation/acceptance view, not a claim that every capability is equivalent to an enterprise-grade SIEM/ITSM module. For example, response playbook checklist state is browser-local, family attribution is not automatically asserted, and classification accuracy is not calculated from unlabeled scans. Runtime telemetry, comprehensive maintained YARA signatures and model compatibility still depend on environment/configuration described in `VERIFICATION_REPORT.md`.
