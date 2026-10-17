# ThreatLens AI — Current Verification Notes

Updated: 2026-10-17

## Current implementation checks

- The active artifact is the supplied Random Forest pipeline at `backend/ml/artifacts/candidates/user_supplied_random_forest_2026-10-16/threatlens_pe_random_forest.joblib`; its paired schema is configured and both declare the same 72 feature names in the same order. The runtime is scikit-learn 1.9.1, matching the artifact version.
- `/api/model/readiness` reports the model and schema loadable with no mismatch.
- An inert PE canary was parsed without execution. It produced real hashes and PE metadata. The model returned a Benign partial estimate with 48/72 features observed; 24 inputs were filled by the estimator's fitted imputers, including all 16 runtime telemetry fields. This validates the software path only, not accuracy or ground truth.
- Production YARA rules are empty by default. The former generic demonstration rule is removed from the runtime image. A harmless rule exists only under `backend/tests/fixtures/rules/` for isolated automated testing.
- Scan detail evidence is extracted from uploaded bytes; no synthetic threat-indicator panel/code sample is injected. Role dashboards show an empty state when there are no persisted scans.
- Python source compilation passed. The Vite production build passed; Vite warned that the separate chart bundle exceeds 500 kB.

## Checks blocked or still needed

- `pytest` could not collect tests in this environment: Starlette's `TestClient` requires the `httpx2` package, which is not installed. This is a test-environment dependency issue; it is not a passing backend suite.
- No independent labeled PE holdout was available. The model's reported 99.1% accuracy is from its saved random split and is not live accuracy. Its top-ranked signals include runtime process/file/registry/network observations unavailable to a static scanner.
- Browser-based testing of all four roles and their workflows was not performed during this audit.
- The local source changes have not been pushed to GitHub or redeployed to Render.

## Interpretation

The model is structurally integrated and can make a partial prediction on supported PE files. It is not “perfectly” validated for static-file use: the 72-feature training schema contains 16 runtime telemetry fields, and static analysis cannot observe them. The app uses only the model's fitted imputers for those absent inputs, displays missingness/coverage, and labels the output as a partial estimate. Treat it as an experimental triage signal until a static-only model or matching measured sandbox telemetry is validated on an independent dataset.

Test fixtures are synthetic and harmless by design. They remain under test-only directories and are not used as real detections or included in the backend runtime image.
