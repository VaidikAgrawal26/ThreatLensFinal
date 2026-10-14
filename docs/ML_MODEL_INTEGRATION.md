# ML Model Integration and Validation

## Artifact contract
Expected files:
```text
backend/ml/artifacts/
  malware_classifier.pkl
  feature_schema.json
  metrics.json            # optional but recommended from the same training run
```
The artifact and schema must originate from the same training run. Do not rename another model to `malware_classifier.pkl` and assume compatibility. Joblib/pickle artifacts must be trusted because deserialization can execute code.

## Schema parsing
The adapter reads feature names from `feature_names`, `feature_columns_in_input_order`, `feature_columns`, `features`, or `columns`. It rejects an empty schema and duplicate names. If the loaded estimator exposes `feature_names_in_`, its order must match the schema. Inference is skipped when required fields are missing; the service does not fill unknown fields with zero or invented behavior values.

## Features the live extractor can measure
For valid PE files, the extractor attempts DOS/file/optional-header fields, section entropy/size/address/characteristics summaries, import-derived suspicious-function counts, and data-directory metadata. Generic file size/entropy, string counts, URL/IP counts and selected indicators are also recorded. Feature extraction requires `pefile` for PE structure parsing.

## Features it cannot infer from a static file alone
Actual registry reads/writes, process creation, runtime network activity, API call sequences, memory behavior and similar telemetry require dynamic instrumentation or an appropriate labeled telemetry source. A string naming a registry key or API is not proof that the behavior occurred. Such fields remain missing, so a model that requires them is marked unavailable.

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

The backend includes `backend/ml/artifacts/malware_classifier.pkl`, its exact `feature_schema.json`, model comparison and evaluation artifacts, top-100 feature importance, and a separate Random Forest pipeline. The default configured artifact is the LightGBM `malware_classifier.pkl`. The authenticated endpoint `GET /api/model/evaluation` returns the supplied metrics and comparisons and explicitly marks them as training artifacts, not live scan accuracy.

The active schema contains 72 features, including runtime behaviour fields that static file parsing cannot measure. If those features are absent, live inference is skipped and missing fields are returned. Do not manufacture zero values for unknown registry/network/process activity. The supplied model artifacts were serialized with scikit-learn 1.9.0; install the pinned requirements. The supplied `metrics.json` and `classification_report.txt` disagree on accuracy (99.55% vs 99.10%), and the API reports that discrepancy rather than silently reconciling it.
