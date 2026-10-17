# Model validation review

## Finding

The supplied files do not prove that the malware model is overfit. They also do not provide enough evidence to rule overfitting or data leakage out. The supplied training notebook clarifies the Random Forest run and its random split, but it does not include the diagnostics or grouped/independent evaluation needed to establish generalization.

## What was inspected

- The PDF project brief describes a malware-classification and static-analysis platform.
- `ThreatLens_PE_Malware_Training.ipynb` loads `ankamteja/pe-malware-detection`, reports 21,752 rows and 77 columns, samples 5,000 rows from each class, and creates an 8,000/2,000 stratified random train/test split (seed 42).
- The notebook removes exact duplicate rows (it found zero), excludes hash and label-like columns, imputes missing values and one-hot encodes categorical columns inside a scikit-learn pipeline, then trains a 250-tree `RandomForestClassifier`.
- Its saved notebook output reports 99.10% accuracy, 98.71% malware precision, 99.50% malware recall, 99.10% malware F1, and 0.999653 ROC-AUC on the 2,000-row test split. A classification report is present, but no training-set score, learning curve, cross-validation, grouped split, independent-source holdout, confidence interval, or threshold analysis is reported.
- The training notebook's model is Random Forest, whereas the repository's current `metrics.json` and feature schema identify LightGBM. The notebook's 99.10% classification report matches the repository report, but the repository metrics file reports 99.55% accuracy and 0.999958 ROC-AUC. These files therefore do not form one reproducible, internally consistent model release; the saved report alone cannot establish which serialized model produced it.
- Removing exact duplicate rows is useful but does not show that duplicate hashes, related malware families, source batches, or collection periods are separated between train and test. Hashes are excluded as features, but the notebook does not use them to group the split.
- Several influential inputs (`processes_malicious`, `files_malicious`, registry and network telemetry) are behavior-derived. They may be legitimate for a sandbox-analysis model, but cannot be obtained from static PE parsing alone. Their availability and label-generation process must be checked; if labels or post-analysis outcomes influenced them, they could leak the target. The model also has 72 inputs, primarily PE fields plus those behavior features.
- The notebook correctly places imputers and one-hot encoding inside the pipeline, and fits that pipeline only on the training partition. This reduces preprocessing leakage. It does not address related-sample leakage, model selection bias, or deployment distribution shift.

## Overfitting versus leakage

- **Overfitting** means the model learned training-specific patterns that do not generalize. Evidence would include a large train/validation gap or materially worse performance on a sound, independent test set.
- **Data leakage** means information unavailable for a genuinely new sample entered training/evaluation, or related/duplicate samples crossed the split. A random row split can look excellent when near-duplicate files or source-specific artifacts appear on both sides.
- **Distribution mismatch** means the evaluation data and deployment files differ. Even a model that generalizes well within its source dataset can fail on different malware families, collection dates, file packers or benign software.
- **Metric inconsistency** means the saved results may come from different runs/splits or contain a reporting error. The 99.55% and 99.10% figures must not be merged into one result.

## Recommended remediation

1. The project now selects the user-supplied Random Forest and its paired schema. Re-run evaluation from this exact serialized model, regenerate `metrics.json` and the classification report together, and record model/data hashes and library versions before relying on the reported score.
2. Retain the pipeline-based preprocessing. Extend the evaluation to report train and validation/test metrics together, learning curves, confusion matrix, per-class precision/recall/F1/support, balanced accuracy, PR-AUC, ROC-AUC, false-positive rate, confidence intervals, and the threshold-selection policy.
3. Check duplicate hashes in addition to exact duplicate rows. Where family, source, campaign, collection batch, or time identifiers are available, keep those groups wholly on one side of the split. Compare a grouped holdout and an out-of-time or independent-source holdout with the current random split.
4. Keep one final test set untouched while tuning. Use grouped cross-validation on the training data for model selection, then evaluate the chosen model once on the untouched test set.
5. Audit feature provenance and label timing, especially behavior-derived process, file, registry, and network features. Remove any field that is a direct label proxy or would not be available at prediction time.
6. Train separate, clearly named models if needed: a static PE model using fields extracted before execution, and a sandbox behavior model using telemetry measured in an isolated analysis environment. Do not silently substitute missing telemetry with zeroes.
7. Evaluate the selected Random Forest on the same grouped and independent holdouts. If scores fall sharply from the saved random split, investigate leakage and distribution shift before changing thresholds or relying on it.
8. Package the selected model, ordered feature schema, preprocessing pipeline, library versions, evaluation report, dataset version, split manifest, and artifact hashes together. Recompute every saved metric from the final serialized artifact before release.

Pipelines help prevent preprocessing leakage; grouped cross-validation prevents related groups from being split across training and test folds; nested validation reduces model-selection bias. See the official [scikit-learn leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html), [grouped cross-validation guidance](https://scikit-learn.org/stable/modules/cross_validation.html#cross-validation-iterators-for-grouped-data), and [nested cross-validation example](https://scikit-learn.org/stable/auto_examples/model_selection/plot_nested_cross_validation_iris.html).

## Conclusion

The practical next step is to obtain the malware training source and data provenance, correct the feature contract, and reproduce evaluation on a duplicate-aware, independent holdout. Until then, label the bundled model metrics as unverified artifacts and do not describe the current scan workflow as achieving 99% malware-detection accuracy.
