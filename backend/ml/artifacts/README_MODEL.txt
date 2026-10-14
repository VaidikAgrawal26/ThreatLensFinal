MODEL ARTIFACT REQUIREMENTS

Place the user's trained model at: backend/ml/artifacts/malware_classifier.pkl
Place its matching schema at: backend/ml/artifacts/feature_schema.json
Set MODEL_PATH and FEATURE_SCHEMA_PATH in backend/.env if the paths differ.

The two artifacts must come from the same training run and use the same feature names/order and preprocessing. This repository intentionally does not bundle a substitute model or invent missing feature values. The current live static extractor emits a limited set of file-derived features. If the schema requires telemetry such as registry/process/network behavior that is not observed during static analysis, inference returns unavailable with the missing feature list. Capture those features from a valid source or retrain a model against the supported static feature set; do not fill them with arbitrary zeroes.

A successful model load does not itself establish model quality. Validate using held-out labeled data and record scikit-learn/joblib versions, preprocessing, class labels, and metrics.
