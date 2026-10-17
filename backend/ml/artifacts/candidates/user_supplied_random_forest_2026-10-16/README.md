# User-supplied Random Forest training artifact

These files were first copied from artifacts supplied on 2026-10-16. The owner re-supplied the Random Forest and `feature_importance_top100.csv` on 2026-10-17; both files were verified byte-for-byte identical to the preserved copies, so no duplicate artifact was added. The model SHA-256 is `e77335f1b53fa0ed422c3b15e3730e6063d3a5c6ef30595e661583fa46aa70c5`; the feature-importance CSV SHA-256 is `bcc14bed4e3eb29d6622befc435558be8395731ac8cab956d2a5ed3a462f6f7c`. The serialized estimator was inspected previously in the project's Python environment: it is a scikit-learn `Pipeline` with a `ColumnTransformer` and `RandomForestClassifier`, 72 input features, and classes `[0, 1]`.

## Training record

- Dataset: `ankamteja/pe-malware-detection`
- Reported subset: 10,000 rows; 8,000 training and 2,000 test rows
- Reported accuracy: 99.10%; malware precision: 98.71%; malware recall: 99.50%; malware F1: 99.10%; ROC-AUC: 0.999653
- The model was serialized with scikit-learn 1.9.1. The backend now pins this exact version.
- The schema is the same ordered 72-feature schema already present in the project. The model artifact is a different file from the project's existing Random Forest artifact.

## Project selection: active final Random Forest

This is not an EMBER2024 model. The application now selects it as the final configured classifier. Its 72-feature schema includes runtime telemetry for registry, network, process, and file activity that static inspection cannot observe. The fitted pipeline uses its training-time numeric median and categorical most-frequent imputers for missing inputs; the backend exposes static input coverage, missing fields, and categorical values outside the fitted vocabulary on every partial estimate. This enables a result for supported PE uploads without claiming runtime behavior was measured.

The re-supplied feature-importance file ranks `numeric__processes_malicious` first, followed by `numeric__files_malicious`, registry activity, and network/process/file telemetry. These are transformed feature names from the pipeline, not a replacement for the full 72-column input schema. They further confirm that the model's strongest signals depend on observations unavailable to a static PE upload scan; the CSV cannot be used to synthesize those values or generate a malware file.

For stronger operational accuracy, validate against a recent independent static-only holdout or provide trusted sandbox telemetry matching the training feature definitions. The reported random split does not establish performance on future or operational files. Do not treat the training report as live accuracy or generate executable malware from the feature list. Safe, inert test fixtures can validate upload, parsing, and reporting workflows.
