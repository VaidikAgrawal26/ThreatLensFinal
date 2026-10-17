MODEL ARTIFACT REQUIREMENTS

The active final model and its paired schema are in `backend/ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/`. Local settings default to this Random Forest bundle; Docker Compose uses the same paths. The fitted pipeline contains numeric median and categorical most-frequent imputers. When a static upload lacks runtime telemetry, the backend passes missing values through as NaN for the fitted imputers and labels the resulting output as a partial estimate with feature coverage. It never reports imputed values as measured behavior.

Use the pinned scikit-learn 1.9.1 requirements. A successful load does not establish live model quality: the supplied evaluation is from a 10,000-row random split and should be independently validated before operational reliance.
