# ML Traffic Classification

The ML boundary is `server/ml_pipeline.py`.

## Evidence boundary

The model may classify encrypted ESP traffic behavior only. It does not infer cipher, key size, DH, PFS, tunnel mode, authentication, or any other cryptographic protocol field.

Features are derived from packet lengths, timing, duration, direction counts/bytes, burst statistics, and packet-size entropy. Raw IP addresses, MAC addresses, filenames, SPIs, and sequence numbers are excluded from model features to prevent identity/session leakage.

## Dataset contract

The training manifest must be a JSON array. Every record requires an externally controlled `capture_id`, `label`, and packet metadata list. Labels must come from controlled ground truth, not from the same classifier.

Training uses `GroupShuffleSplit` by capture ID so windows from one capture cannot appear in both train and test partitions. Missing labels, too few capture groups, and insufficient class diversity return `INSUFFICIENT_DATA` or `NOT_DETERMINABLE`.

Random Forest and HistGradientBoosting baselines are evaluated with accuracy, macro precision/recall/F1, weighted F1, per-class report, and confusion matrix. XGBoost is optional and is reported as unavailable when its dependency is absent; no benchmark is fabricated.

The current dashboard heuristic classifier remains a compatibility baseline. It is marked as `ML_INFERENCE` but is not a trained production model until a controlled dataset is supplied and grouped evaluation results are reviewed.