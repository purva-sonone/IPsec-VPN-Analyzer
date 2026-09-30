"""
train_classifier.py — VNAT Traffic Category Classifier Training Script

Dataset: VNAT Feature Dataframe Release 1 (MIT Lincoln Laboratory)
Source:  https://archive.ll.mit.edu/datasets/vnat/VNAT_Feature_Dataframe_release_1.h5
Size:    8.6 MB (15,093 samples, 130 columns including label)

DATASET NOTES:
- Labels are traffic CATEGORIES: C2, CHAT, FILE_TRANSFER, STREAMING, VOIP
- These represent traffic captured BOTH inside and outside VPN tunnels
- The VPN/non-VPN binary distinction is NOT available in this file (requires 32GB PCAP archive)
- We train a 5-class TRAFFIC CATEGORY classifier using only features
  extractable at inference time from a PCAP upload

FEATURES SELECTED (17 features, all extractable from packet-level data):
  Flow inter-arrival time (IAT) statistics:
    out_iat_min, out_iat_max, out_iat_mean, out_iat_std_dev
    in_iat_min, in_iat_max, in_iat_mean, in_iat_std_dev
    flow_iat_min, flow_iat_max, flow_iat_mean, flow_iat_std_dev
  Flow volume/rate:
    log_bytes_per_sec
    log_total_outgoing_packets, log_total_incoming_packets
    log_total_outgoing_bytes, log_total_incoming_bytes

MODEL: RandomForestClassifier (tuned for maximum accuracy)
  - n_estimators=500 (up from 200)
  - max_features='sqrt'
  - min_samples_leaf=1
  - random_state=42 for reproducibility
  - stratified 80/20 train/test split
  - no data leakage (labels only from 'labels' column)
"""

import pandas as pd
import numpy as np
import json
import joblib
import os
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)
from sklearn.preprocessing import LabelEncoder

# ─── Configuration ────────────────────────────────────────────────────────────

RANDOM_STATE  = 42
TEST_SIZE     = 0.20
H5_FILE       = "backend/data/VNAT_Feature_Dataframe_release_1.h5"
MODEL_PATH    = "backend/models/traffic_classifier.joblib"
METADATA_PATH = "backend/models/classifier_metadata.json"

FEATURE_COLS = [
    'out_iat_min',   'out_iat_max',   'out_iat_mean',   'out_iat_std_dev',
    'in_iat_min',    'in_iat_max',    'in_iat_mean',    'in_iat_std_dev',
    'flow_iat_min',  'flow_iat_max',  'flow_iat_mean',  'flow_iat_std_dev',
    'log_bytes_per_sec',
    'log_total_outgoing_packets', 'log_total_incoming_packets',
    'log_total_outgoing_bytes',   'log_total_incoming_bytes',
]

LABEL_COL = 'labels'

# ─── Load Dataset ─────────────────────────────────────────────────────────────

print("=" * 60)
print("VNAT Traffic Category Classifier - Training (Optimized)")
print("=" * 60)

print(f"\n[1/6] Loading dataset: {H5_FILE}")
df = pd.read_hdf(H5_FILE)
print(f"  Loaded {len(df):,} rows × {len(df.columns)} columns")
print(f"  Label distribution:")
label_counts = df[LABEL_COL].value_counts()
for label, count in label_counts.items():
    print(f"    {label}: {count:,}")

# ─── Verify Feature Availability ─────────────────────────────────────────────

print(f"\n[2/6] Verifying feature availability")
missing_cols = [c for c in FEATURE_COLS if c not in df.columns]
if missing_cols:
    raise ValueError(f"Missing expected feature columns: {missing_cols}")
print(f"  All {len(FEATURE_COLS)} features present")
null_counts = df[FEATURE_COLS].isnull().sum()
if null_counts.any():
    print(f"  WARNING: Null values found — filling with 0")
    df[FEATURE_COLS] = df[FEATURE_COLS].fillna(0)
else:
    print("  No null values in feature columns")

# ─── Prepare X and y ─────────────────────────────────────────────────────────

print(f"\n[3/6] Preparing features and labels")
X = df[FEATURE_COLS].values
y = df[LABEL_COL].values

# Encode labels to integers for sklearn
le = LabelEncoder()
y_enc = le.fit_transform(y)
classes = list(le.classes_)
print(f"  Classes: {classes}")
print(f"  Encoded: {list(range(len(classes)))}")

# ─── Train/Test Split ─────────────────────────────────────────────────────────

print(f"\n[4/6] Stratified train/test split (80/20, seed={RANDOM_STATE})")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_enc,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=y_enc,
)
print(f"  Train: {len(X_train):,} samples")
print(f"  Test:  {len(X_test):,} samples")

# Per-class train/test breakdown
for i, cls in enumerate(classes):
    tr = (y_train == i).sum()
    te = (y_test == i).sum()
    print(f"    {cls}: train={tr}, test={te}")

# ─── Train Optimized RandomForest ─────────────────────────────────────────────

print(f"\n[5/6] Training Optimized RandomForestClassifier")
print("  - n_estimators: 500 (up from 200)")
print("  - max_features: sqrt")
print("  - min_samples_leaf: 1")
print("  - class_weight: balanced_subsample")

clf = RandomForestClassifier(
    n_estimators=500,          # more trees = more stable, higher accuracy
    max_depth=None,            # fully grown trees
    min_samples_split=2,
    min_samples_leaf=1,
    max_features='sqrt',       # standard best practice for RF
    class_weight='balanced_subsample',  # handles VOIP class imbalance better
    random_state=RANDOM_STATE,
    n_jobs=-1,                 # use all CPU cores
    oob_score=True,            # out-of-bag score for extra validation
    bootstrap=True,
)
clf.fit(X_train, y_train)
print(f"  Trained {clf.n_estimators} trees")
print(f"  OOB Score (extra validation): {clf.oob_score_:.4f} ({clf.oob_score_*100:.2f}%)")

# ─── Evaluate ─────────────────────────────────────────────────────────────────

print(f"\n[6/6] Evaluation on test set")
y_pred = clf.predict(X_test)

acc = accuracy_score(y_test, y_pred)
report = classification_report(
    y_test, y_pred,
    target_names=classes,
    output_dict=True,
)
cm = confusion_matrix(y_test, y_pred)

print(f"\n  [DONE] Test Accuracy: {acc:.4f} ({acc*100:.2f}%)")
print(f"\n  Per-class metrics:")
print(f"  {'Class':<20} {'Precision':>10} {'Recall':>10} {'F1-score':>10} {'Support':>10}")
print(f"  {'-'*60}")
for cls in classes:
    m = report[cls]
    print(f"  {cls:<20} {m['precision']:>10.4f} {m['recall']:>10.4f} {m['f1-score']:>10.4f} {m['support']:>10.0f}")
print(f"\n  Macro avg:           {report['macro avg']['precision']:>10.4f} {report['macro avg']['recall']:>10.4f} {report['macro avg']['f1-score']:>10.4f}")
print(f"  Weighted avg:        {report['weighted avg']['precision']:>10.4f} {report['weighted avg']['recall']:>10.4f} {report['weighted avg']['f1-score']:>10.4f}")

print(f"\n  Confusion Matrix (rows=true, cols=predicted):")
print(f"  Classes: {classes}")
for i, row in enumerate(cm):
    print(f"  {classes[i]:<15}: {list(row)}")

# ─── Feature Importance ───────────────────────────────────────────────────────

importances = dict(sorted(
    zip(FEATURE_COLS, clf.feature_importances_),
    key=lambda x: x[1], reverse=True
))
print(f"\n  Top 10 feature importances:")
for i, (feat, imp) in enumerate(importances.items()):
    if i >= 10:
        break
    print(f"    {feat:<40}: {imp:.4f}")

# ─── Save Model and Metadata ──────────────────────────────────────────────────

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
joblib.dump({'model': clf, 'label_encoder': le}, MODEL_PATH)
print(f"\n  Model saved: {MODEL_PATH}")

metadata = {
    "dataset_source": "MIT Lincoln Laboratory VNAT Dataset",
    "dataset_url": "https://archive.ll.mit.edu/datasets/vnat/VNAT_Feature_Dataframe_release_1.h5",
    "dataset_file": "VNAT_Feature_Dataframe_release_1.h5",
    "dataset_size_mb": round(os.path.getsize(H5_FILE) / 1024 / 1024, 2),
    "total_samples": len(df),
    "train_samples": len(X_train),
    "test_samples": len(X_test),
    "label_distribution": label_counts.to_dict(),
    "classifier_task": "Traffic Category Classification (5-class)",
    "classes": classes,
    "label_note": (
        "Labels represent application traffic categories from VNAT dataset. "
        "VPN/non-VPN binary distinction is NOT available in this feature file; "
        "it requires the 32GB PCAP archive. This classifier predicts traffic "
        "category (C2, CHAT, FILE_TRANSFER, STREAMING, VOIP), which is useful "
        "for identifying anomalous traffic types inside IPsec VPN tunnels."
    ),
    "feature_names": FEATURE_COLS,
    "n_features": len(FEATURE_COLS),
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
}

with open(METADATA_PATH, "w") as f:
    json.dump(metadata, f, indent=2, default=str)
print(f"  Metadata saved: {METADATA_PATH}")

print(f"\n{'='*60}")
print(f"TRAINING COMPLETE")
print(f"  Accuracy: {acc*100:.2f}%")
print(f"  OOB:      {clf.oob_score_*100:.2f}%")
print(f"  Model:    {MODEL_PATH}")
print(f"{'='*60}")
