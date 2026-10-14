# ThreatLens AI — Verification Notes

Updated: 2026-10-14

## Changes in this package
- Login and signup present all four roles: Administrator, Security Analyst, SOC Team Member, and Researcher. The backend checks login role against the role saved on the account.
- Researcher registration is activated immediately; other public role requests are pending until an administrator activates them. Administrator registration cannot grant the caller administrative permissions.
- SOC Team Members can monitor but cannot upload samples. Administrator, Security Analyst, and Researcher roles may upload files.
- The supplied `malware_classifier.pkl`, `threatlens_pe_random_forest.joblib`, `feature_schema.json`, metrics, comparison, classification report, and feature-importance artifacts are included and hash-compared with the uploaded files during packaging. The schema and model declare 72 features in the same order.
- Every completed scan response includes a separate, clearly labelled synthetic demo-indicator panel and non-executable code preview. It is not extracted evidence, not a real YARA match, and does not affect risk or verdict.
- The dashboard uses actual stored scans for its ten ECharts visualizations when available. Before any scans are stored, it shows visibly labelled demo observations so chart components are populated. These are not persisted or presented as real detections.
- The upload response continues to contain real file hashes, measured strings/indicators, YARA results, static metadata, and model status separately from the demo preview. Uploaded samples are not executed.

## Checks run in this workspace
- Backend tests: **30 passed, 2 skipped**.
- Python source compilation: **passed**.
- Model/schema test: **72 schema features; model declares 72 features in the same order**.
- A synthetic model-inference test passed in the current environment after bypassing the runtime compatibility guard specifically in that test. This does not validate real-world predictions.

## Remaining verification limits
- The available test environment has scikit-learn **1.8.0**, while the supplied model was serialized with scikit-learn **1.9.0**. Warnings were observed during artifact loading. The application intentionally marks live inference unavailable until run with the pinned compatible dependencies. Install `backend/requirements.txt` in a fresh environment before relying on inference.
- Frontend dependency installation did not finish in the available workspace, so a Vite production build and browser end-to-end test were not run. The modified JSX was parser-checked separately; this is not a substitute for a production build.
- Two YARA tests were skipped because the YARA engine was unavailable in the test environment. Install `yara-python` from backend requirements to exercise YARA integration.
- The synthetic indicator preview and empty-dashboard demo charts are for interface demonstration only. They are not real detections, and their values must not be used to evaluate model quality. Offline metrics describe the supplied test split only, not live accuracy.
