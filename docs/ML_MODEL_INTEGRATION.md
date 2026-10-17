# ML Model Integration and Validation

## Artifact contract
Expected files:
```text
backend/ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/
  threatlens_pe_random_forest.joblib
  feature_schema.json
  metrics.json
  classification_report.txt
  feature_importance_top100.csv
```
The active model path defaults to this model and its paired schema. The former LightGBM files remain in the artifacts directory for rollback, but are no longer selected by default. Joblib/pickle artifacts must be trusted because deserialization can execute code.

## Schema parsing
The adapter reads feature names from `feature_names`, `feature_columns_in_input_order`, `feature_columns`, `features`, or `columns`. It rejects an empty schema and duplicate names. If the loaded estimator exposes `feature_names_in_`, its order must match the schema. For valid PE inputs, the final Random Forest's fitted numeric median and categorical most-frequent imputers process schema fields unavailable to static scanning. Missing runtime values remain NaN at the adapter boundary; the scan result records the omitted names, percentage of directly observed features, and any categorical values outside the training vocabulary. They are never reported as measured activity.

## Features the live extractor can measure
For valid PE files, the extractor attempts DOS/file/optional-header fields, section entropy/size/address/characteristics summaries, import-derived suspicious-function counts, and data-directory metadata. Generic file size/entropy, string counts, URL/IP counts and selected indicators are also recorded. Feature extraction requires `pefile` for PE structure parsing.

## Features it cannot infer from a static file alone
Actual registry reads/writes, process creation, runtime network activity, API call sequences, memory behavior and similar telemetry require dynamic instrumentation or an appropriate labeled telemetry source. A string naming a registry key or API is not proof that the behavior occurred. These features are median/mode-imputed by the fitted model for a partial static estimate and are explicitly surfaced as unobserved; their absence can reduce prediction quality.

## Label and score handling
The adapter maps common binary labels such as `1`/`Malware` and `0`/`Benign`. If `predict_proba` is available, it reports the model's corresponding Malware-class score when the class mapping can be determined. This value is not necessarily calibrated probability. Always display model unavailability/errors separately from a benign prediction.

## Validation checklist
1. Verify artifact and schema are present at configured paths.
2. Verify `schema_feature_count` and exact names/order.
3. Confirm feature definitions, units, preprocessing, missing-value handling and category encoding match training.
4. Align scikit-learn and dependent library versions with the training environment.
5. Test known benign/malicious labeled holdout examples in a controlled environment; inspect individual errors.
6. Record precision, recall, F1, ROC-AUC/PR-AUC only on labeled held-out data with the correct denominator.
7. Compare model-only, YARA-only and heuristic results separately. Do not train or report ML accuracy from unlabeled production uploads.
8. Do not claim end-to-end model verification until the actual model and paired schema are installed and tests pass.

## Owner-supplied artifacts (integrated)

The active configured artifact is the user's Random Forest under `backend/ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/`. Docker Compose and local defaults point to its matching schema. The authenticated endpoint `GET /api/model/evaluation` returns this bundle's report, metrics and top-100 feature importance as training artifacts, not live scan accuracy.

The active schema contains 72 features, including runtime behavior fields that static file parsing cannot measure. The fitted training-time imputers let PE scans run with missing inputs, and every partial result includes coverage and missing-field details. Install the pinned scikit-learn 1.9.1 requirement. The Random Forest reports 99.10% accuracy on its saved random 2,000-row holdout; this is not a live-performance guarantee and is not evidence against source/family leakage.

## Selected final Random Forest (re-verified 2026-10-17)

The re-supplied model and feature-importance CSV were verified byte-identical to the preserved artifacts. The paired schema and metrics are included in the same bundle. This model uses the earlier `ankamteja/pe-malware-detection` dataset and is separate from the EMBER2024 notebook. Its top-ranked features are runtime process, file, registry and network observations. The service now produces a partial static estimate for a valid PE using the pipeline's fitted imputers for unavailable fields and shows coverage/missingness; this is a compatibility path, not a substitute for a static-only trained model or sandbox telemetry. See the candidate README for hashes, metrics and validation limits.
