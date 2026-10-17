# ThreatLens model artifacts supplied by the project owner

## Active final artifact

- `candidates/user_supplied_random_forest_2026-10-16/threatlens_pe_random_forest.joblib`: active scikit-learn Random Forest pipeline.
- The same directory contains its ordered 72-column schema, metrics, classification report, and feature-importance CSV.
- `malware_classifier.pkl` and root-level metrics are preserved as the previous LightGBM release; the application defaults now select the Random Forest bundle.

## Compatibility

The active Random Forest was serialized with scikit-learn 1.9.1. `backend/requirements.txt` pins that exact version; readiness refuses inference under another version to avoid pickle compatibility warnings and behavior changes.

## Important feature limitation

The selected schema has 72 fields. It includes PE header/section fields and behavioural fields such as registry operations, network activity, process counts, and observed file activity. A static upload scanner cannot observe runtime behavior. The active pipeline's fitted numeric median and categorical most-frequent imputers are used for missing training-schema values so PE scans can still receive a model estimate. Results expose partial input coverage and missing runtime features; imputed values are not presented as observations. Treat output as a triage estimate and validate against labeled static-only data before operational use.

## Evaluation figures are training artifacts, not live performance

The active Random Forest bundle reports 99.10% accuracy on its 2,000-row random test split from a 10,000-row dataset. This is a training artifact, not live scan accuracy; assess it on a duplicate-aware, temporal or independent-source holdout before operational claims.

## Security

Only load model artifacts from trusted sources. Do not replace the artifact with a downloaded or unverified pickle/joblib file.
