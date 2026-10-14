# ThreatLens AI verification report

## Verification run in this environment (2026-10-12)

### Passed

- Backend suite: `PYTHONPATH=. pytest -q` — **26 passed, 2 skipped**.
- Frontend syntax transpilation: `App.jsx` and `main.jsx` — **0 TypeScript transpilation diagnostics**.
- Model/schema structural check: supplied `malware_classifier.pkl` loads in the current environment and exposes 72 `feature_names_in_` entries; the 72 entries match `feature_columns_in_input_order` in `feature_schema.json` in exact order.
- ZIP archive integrity: verified after packaging.

### Not passed / not run (do not treat as verified)

- **Frontend production build:** not run. `npm install --no-audit --no-fund` timed out. The environment could not resolve `registry.npmjs.org`; no Vite or React dependencies are installed locally.
- **Live YARA integration:** two tests are skipped because `yara-python` is not installed. The attempt to install dependencies failed because package-registry DNS resolution was unavailable. Only the illustrative demo rule is bundled.
- **PE parsing against real executable fixtures:** `pefile` is not installed, and dependency installation could not reach the package index.
- **Model inference in a compatible runtime:** the artifact can be loaded with scikit-learn 1.8.0, but emits `InconsistentVersionWarning` because it was serialized with scikit-learn 1.9.0. This warning means prediction correctness is not certified. The service deliberately reports the mismatch instead of declaring inference ready.
- **Representative live model prediction:** not verified. No labelled executable test corpus was available, and runtime-behaviour fields (registry/network/process/file telemetry) cannot be inferred from static PE bytes alone.
- **All 40 capabilities end to end:** not independently exercised in a browser. The inventory has 40 distinct identifiers/workspace cases, but the existence of a workspace is not proof every capability passes acceptance tests.
- **All 40 chart placements:** not verified in a running browser. Chart definitions and scan-derived data logic are present in the frontend source, but a production bundle and browser run were unavailable.
- **Full browser and role-authorization testing:** not run. Backend authorization tests pass for covered routes, but this is not a substitute for testing all browser workflows and every API action for all roles.

## Reproducible local verification

Run from the project root on a machine with package-registry access:

- Windows PowerShell: `./scripts/verify-local.ps1`
- macOS/Linux: `./scripts/verify-local.sh`

These scripts install backend/frontend dependencies, run the backend suite and run the Vite production build. They do not claim to replace manual/browser acceptance tests. Follow `docs/TESTING.md` to test actual uploads, model readiness, YARA positive/negative fixtures, all role workflows, and access-control boundaries.

## Important safety and interpretation notes

- A schema-valid model artifact is not proof of valid prediction on a particular upload.
- Do not invent values for missing runtime telemetry. If the trained model requires unavailable fields, return an explicit inference-unavailable status or use a model trained for available static features.
- YARA matches are evidence, not proof of malware; no match does not establish benignness.
- Accuracy, precision, recall, F1 and ROC-AUC must be based on independent labelled evaluation data, not unlabelled production scans.
- The included ruleset is a demo rule, not a comprehensive maintained production ruleset.
