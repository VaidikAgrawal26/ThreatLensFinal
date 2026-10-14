# ThreatLens model artifacts supplied by the project owner

## Primary artifact

- `malware_classifier.pkl`: selected LightGBM sklearn Pipeline.
- `feature_schema.json`: ordered 72-column input schema used by that pipeline.
- `metrics.json`, `model_comparison.csv`, `classification_report.txt`, and `feature_importance_top100.csv`: supplied training evaluation artifacts.
- `threatlens_pe_random_forest.joblib`: separate Random Forest pipeline artifact; it is not the active model configured by default.

## Compatibility

The supplied pipelines were serialized with scikit-learn 1.9.0. `requirements.txt` pins scikit-learn 1.9.0 and LightGBM 4.6.0. Loading a pickle/joblib file under a different scikit-learn version can fail or behave differently; the API readiness check refuses to advertise model inference as ready on a different sklearn minor version.

## Important feature limitation

The selected schema has 72 fields. It includes PE header/section fields and behavioural fields such as registry operations, network activity, process counts, and observed file activity. A static upload scanner cannot truthfully observe runtime behaviour without sandbox/endpoint telemetry. ThreatLens therefore reports missing features and skips inference rather than filling unknown behaviour with zeros or invented values. To make live ML classification available for arbitrary uploads, either integrate trusted sandbox telemetry that produces these exact definitions or retrain a model on features the static analyzer actually extracts.

## Evaluation figures are training artifacts, not live performance

The supplied `metrics.json` reports LightGBM accuracy 0.9955 (99.55%), while `classification_report.txt` reports accuracy 0.9910 (99.10%). These files are preserved as uploaded; the discrepancy is exposed in the API and must be reconciled against the original evaluation run before publication. Neither number describes the accuracy of current production scans.

## Security

Only load model artifacts from trusted sources. Do not replace the artifact with a downloaded or unverified pickle/joblib file.
