"""
train_classifier_v2.py -- VNAT Traffic Category Classifier V2 Training Script

Changes from V1 (train_classifier.py):
  - Drops log_total_outgoing_bytes, log_total_incoming_bytes (identical to packet
    count columns in every row of the dataset -- confirmed 100% equality, Pearson r=1.0)
  - Drops flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std_dev (confirmed
    definition mismatch: dataset uses chronological cross-direction consecutive-packet
    IATs; analyzer.py concatenates per-direction lists -- different computation,
    mismatch in 71.7% of dataset rows)
  - Applies exact-duplicate deduplication before splitting (197 rows removed)
  - Trains on 11 independently verified features
  - Saves to traffic_classifier_v2.joblib and classifier_v2_metadata.json

V1 (train_classifier.py) and its model artifact are NOT modified.
"""

import pandas as pd
import numpy as np
import json
import joblib
import os
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder

RANDOM_STATE  = 42
TEST_SIZE     = 0.20
H5_FILE       = "backend/data/VNAT_Feature_Dataframe_release_1.h5"
MODEL_PATH    = "backend/models/traffic_classifier_v2.joblib"
METADATA_PATH = "backend/models/classifier_v2_metadata.json"

V2_FEATURE_COLS = [
    "out_iat_min",    "out_iat_max",    "out_iat_mean",    "out_iat_std_dev",
    "in_iat_min",     "in_iat_max",     "in_iat_mean",     "in_iat_std_dev",
    "log_bytes_per_sec",
    "log_total_outgoing_packets",
    "log_total_incoming_packets",
]

LABEL_COL = "labels"

EXCLUDED_COLS_REASON = {
    "log_total_outgoing_bytes": (
        "Identical to log_total_outgoing_packets in all 15,093 rows "
        "(100.00% equality, Pearson r=1.0). Provides zero independent signal."
    ),
    "log_total_incoming_bytes": (
        "Identical to log_total_incoming_packets in all 15,093 rows "
        "(100.00% equality, Pearson r=1.0). Provides zero independent signal."
    ),
    "flow_iat_min": (
        "Definition mismatch: dataset uses chronological cross-direction "
        "consecutive-packet IATs; analyzer.py concatenates per-direction lists. "
        "flow_iat_min < min(out_iat_min, in_iat_min) in 71.7% of rows (10,824/15,093)."
    ),
    "flow_iat_max":    "Same mismatch as flow_iat_min (cross-direction vs per-direction IAT).",
    "flow_iat_mean":   "Same mismatch as flow_iat_min (cross-direction vs per-direction IAT).",
    "flow_iat_std_dev":"Same mismatch as flow_iat_min (cross-direction vs per-direction IAT).",
}

VALIDATION_SCOPE_NOTE = (
    "These metrics reflect held-out test-set performance on deduplicated VNAT feature "
    "vectors ONLY. They are NOT real-world PCAP performance estimates. "
    "Pre-dedup: 15,093 rows. Exact duplicates removed: 197. Post-dedup: 14,896. "
    "Split: stratified 80/20, random_state=42. "
    "Session-grouped split was NOT possible (no flow IDs in feature file). "
    "Real-world PCAP accuracy may differ due to: heuristic direction inference on "
    "ESP-encrypted flows, high variance in short captures, and controlled lab vs "
    "production traffic differences. "
    "flow_iat_* features excluded due to confirmed training-inference mismatch. "
    "V2 is NOT claimed to be more accurate on real traffic than V1."
)

print("=" * 65)
print("VNAT Traffic Category Classifier V2 -- Training")
print("=" * 65)

print(f"\n[1/7] Loading dataset: {H5_FILE}")
df = pd.read_hdf(H5_FILE)
print(f"  Loaded {len(df):,} rows x {len(df.columns)} columns")
print(f"  Label distribution (pre-dedup):")
label_counts_raw = df[LABEL_COL].value_counts()
for label, count in label_counts_raw.items():
    print(f"    {label}: {count:,}")

print(f"\n[2/7] Exact-duplicate deduplication")
n_before = len(df)
df = df.drop_duplicates()
n_after = len(df)
n_removed = n_before - n_after
print(f"  Rows before dedup: {n_before:,}")
print(f"  Exact duplicates removed: {n_removed:,}")
print(f"  Rows after dedup:  {n_after:,}")
label_counts = df[LABEL_COL].value_counts()
print(f"  Label distribution (post-dedup):")
for label, count in label_counts.items():
    pct = count / n_after * 100
    print(f"    {label}: {count:,} ({pct:.1f}%)")

print(f"\n[3/7] Verifying V2 feature availability ({len(V2_FEATURE_COLS)} features)")
missing_cols = [c for c in V2_FEATURE_COLS if c not in df.columns]
if missing_cols:
    raise ValueError(f"Missing expected V2 feature columns: {missing_cols}")
print(f"  All {len(V2_FEATURE_COLS)} V2 features present")
null_counts = df[V2_FEATURE_COLS].isnull().sum()
if null_counts.any():
    print(f"  WARNING: Null values found -- filling with 0")
    df[V2_FEATURE_COLS] = df[V2_FEATURE_COLS].fillna(0)
else:
    print(f"  No null values in V2 feature columns")
print(f"\n  Excluded columns (6 total):")
for col, reason in EXCLUDED_COLS_REASON.items():
    print(f"    {col}: {reason[:80]}...")

print(f"\n[4/7] Preparing features and labels")
X = df[V2_FEATURE_COLS].values
y = df[LABEL_COL].values
le = LabelEncoder()
y_enc = le.fit_transform(y)
classes = list(le.classes_)
print(f"  Classes: {classes}")

print(f"\n[5/7] Stratified train/test split (80/20, seed={RANDOM_STATE})")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y_enc,
)
print(f"  Train: {len(X_train):,} samples  |  Test: {len(X_test):,} samples")
for i, cls in enumerate(classes):
    tr = (y_train == i).sum()
    te = (y_test == i).sum()
    print(f"    {cls}: train={tr}, test={te}")

print(f"\n[6/7] Training RandomForestClassifier (V2, 11 features)")
clf = RandomForestClassifier(
    n_estimators=500, max_depth=None, min_samples_split=2,
    min_samples_leaf=1, max_features="sqrt",
    class_weight="balanced_subsample",
    random_state=RANDOM_STATE, n_jobs=-1, oob_score=True, bootstrap=True,
)
clf.fit(X_train, y_train)
print(f"  Trained {clf.n_estimators} trees")
print(f"  OOB Score: {clf.oob_score_:.4f} ({clf.oob_score_*100:.2f}%)")

print(f"\n[7/7] Evaluation on held-out test set (VNAT feature vectors only)")
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
cm = confusion_matrix(y_test, y_pred)

print(f"\n  Test Accuracy: {acc:.4f} ({acc*100:.2f}%)")
print(f"\n  Per-class metrics (held-out VNAT test split ONLY -- not real-world PCAP accuracy):")
print(f"  {'Class':<20} {'Precision':>10} {'Recall':>10} {'F1-score':>10} {'Support':>10}")
print(f"  {'-'*62}")
for cls in classes:
    m = report[cls]
    print(f"  {cls:<20} {m['precision']:>10.4f} {m['recall']:>10.4f} "
          f"{m['f1-score']:>10.4f} {int(m['support']):>10d}")
print(f"\n  Macro avg:    {report['macro avg']['precision']:>10.4f} "
      f"{report['macro avg']['recall']:>10.4f} {report['macro avg']['f1-score']:>10.4f}")
print(f"  Weighted avg: {report['weighted avg']['precision']:>10.4f} "
      f"{report['weighted avg']['recall']:>10.4f} {report['weighted avg']['f1-score']:>10.4f}")

print(f"\n  Confusion Matrix (rows=true, cols=predicted):")
print(f"  Classes: {classes}")
for i, row in enumerate(cm):
    print(f"  {classes[i]:<15}: {list(row)}")

importances = dict(sorted(
    zip(V2_FEATURE_COLS, clf.feature_importances_),
    key=lambda x: x[1], reverse=True
))
print(f"\n  Feature importances (V2, 11 features):")
for feat, imp in importances.items():
    print(f"    {feat:<40}: {imp:.4f}")

print(f"\n  VALIDATION SCOPE: {VALIDATION_SCOPE_NOTE[:120]}...")

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
joblib.dump({"model": clf, "label_encoder": le}, MODEL_PATH)
print(f"\n  Model saved: {MODEL_PATH}")

metadata = {
    "version": "v2",
    "dataset_source": "MIT Lincoln Laboratory VNAT Dataset",
    "dataset_url": "https://archive.ll.mit.edu/datasets/vnat/VNAT_Feature_Dataframe_release_1.h5",
    "dataset_file": "VNAT_Feature_Dataframe_release_1.h5",
    "dataset_size_mb": round(os.path.getsize(H5_FILE) / 1024 / 1024, 2),
    "total_samples_pre_dedup": n_before,
    "exact_duplicates_removed": n_removed,
    "total_samples_post_dedup": n_after,
    "train_samples": len(X_train),
    "test_samples": len(X_test),
    "label_distribution_post_dedup": label_counts.to_dict(),
    "classifier_task": "Traffic Category Classification (5-class)",
    "classes": classes,
    "label_note": (
        "Labels represent application traffic categories from VNAT dataset. "
        "VPN/non-VPN binary distinction is NOT available in this feature file; "
        "it requires the 32GB PCAP archive."
    ),
    "feature_names": V2_FEATURE_COLS,
    "n_features": len(V2_FEATURE_COLS),
    "excluded_features": EXCLUDED_COLS_REASON,
    "model_type": "RandomForestClassifier",
    "n_estimators": clf.n_estimators,
    "max_features": "sqrt",
    "class_weight": "balanced_subsample",
    "oob_score": round(clf.oob_score_, 4),
    "random_seed": RANDOM_STATE,
    "test_size": TEST_SIZE,
    "accuracy": round(acc, 4),
    "classification_report": report,
    "confusion_matrix": cm.tolist(),
    "feature_importances": {k: round(v, 6) for k, v in importances.items()},
    "training_date": datetime.now().isoformat(),
    "validation_scope_note": VALIDATION_SCOPE_NOTE,
}

with open(METADATA_PATH, "w") as f:
    json.dump(metadata, f, indent=2, default=str)
print(f"  Metadata saved: {METADATA_PATH}")

print(f"\n{'='*65}")
print(f"V2 TRAINING COMPLETE")
print(f"  Features : {len(V2_FEATURE_COLS)} (V1 has 17)")
print(f"  Accuracy : {acc*100:.2f}%  (held-out VNAT test split only)")
print(f"  OOB      : {clf.oob_score_*100:.2f}%")
print(f"  Model    : {MODEL_PATH}")
print(f"{'='*65}")
