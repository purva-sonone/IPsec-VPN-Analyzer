"""
ml_model.py — Real Traffic Category Classifier using VNAT Dataset

This module uses a RandomForestClassifier trained on the MIT Lincoln Laboratory
VNAT Feature Dataframe (15,093 samples, 5 traffic categories).

IMPORTANT — HONEST LIMITATIONS:
  - The classifier predicts TRAFFIC CATEGORY, not VPN vs non-VPN.
  - Categories: C2 (Command & Control), CHAT, FILE_TRANSFER, STREAMING, VOIP
  - The VNAT Feature Dataframe does not contain VPN/non-VPN binary labels;
    that distinction requires the 32 GB PCAP archive.
  - This classifier is useful for identifying anomalous traffic types inside
    an IPsec VPN tunnel (e.g., detecting C2 traffic hidden inside a VPN).
  - For short captures (< ~20 packets), inter-arrival-time features have
    high variance and predictions should be treated as indicative only.

Model versions:
  v1 (default) — 17 features including flow_iat_* and byte columns.
                 traffic_classifier.joblib
  v2 (opt-in)  — 11 independently verified features; drops flow_iat_* (confirmed
                 training-inference mismatch) and byte columns (100% identical to
                 packet count columns in dataset). traffic_classifier_v2.joblib

Select version via MODEL_VERSION environment variable (default: 'v1').
V2 is NOT claimed to be more accurate on real traffic; it eliminates
known redundant/mismatched features. Real-world accuracy depends on capture
quality and is NOT guaranteed by held-out VNAT test-set metrics.

V1 accuracy on held-out test set (20%, stratified): 98.74%
V2 accuracy on held-out test set (20%, stratified, deduped): 98.76%
Dataset: VNAT_Feature_Dataframe_release_1.h5
         https://archive.ll.mit.edu/datasets/vnat/
"""

import os
import logging
import math

logger = logging.getLogger(__name__)

# ── Model version selection (MODEL_VERSION env-var, default 'v1') ─────────────
# Read once at import time; restart the server to change.

_MODEL_VERSION = os.environ.get('MODEL_VERSION', 'v1').strip().lower()

# ── Model paths ───────────────────────────────────────────────────────────────

_MODELS_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), '..', 'models'))

_MODEL_PATH    = os.path.join(_MODELS_DIR, 'traffic_classifier.joblib')
_MODEL_PATH_V2 = os.path.join(_MODELS_DIR, 'traffic_classifier_v2.joblib')

# ── Feature column order — V1 (must match train_classifier.py exactly) ────────

_FEATURE_COLS = [
    'out_iat_min',   'out_iat_max',   'out_iat_mean',   'out_iat_std_dev',
    'in_iat_min',    'in_iat_max',    'in_iat_mean',    'in_iat_std_dev',
    'flow_iat_min',  'flow_iat_max',  'flow_iat_mean',  'flow_iat_std_dev',
    'log_bytes_per_sec',
    'log_total_outgoing_packets', 'log_total_incoming_packets',
    'log_total_outgoing_bytes',   'log_total_incoming_bytes',
]

# ── Feature column order — V2 (must match train_classifier_v2.py exactly) ─────
# Drops: flow_iat_* (confirmed training-inference mismatch in 71.7% of rows)
#        log_total_outgoing_bytes, log_total_incoming_bytes
#        (100% identical to packet count columns in VNAT dataset)

_V2_FEATURE_COLS = [
    'out_iat_min',   'out_iat_max',   'out_iat_mean',   'out_iat_std_dev',
    'in_iat_min',    'in_iat_max',    'in_iat_mean',    'in_iat_std_dev',
    'log_bytes_per_sec',
    'log_total_outgoing_packets', 'log_total_incoming_packets',
]

# ── Per-version lazy caches (each version loads independently) ────────────────

_clf_cache    = None   # V1
_le_cache     = None   # V1
_v2_clf_cache = None   # V2
_v2_le_cache  = None   # V2


def _load_model(version: str = 'v1'):
    """
    Load the trained model for the requested version.
    Returns (clf, label_encoder) or (None, None) on any failure.

    version='v1' loads traffic_classifier.joblib
    version='v2' loads traffic_classifier_v2.joblib

    IMPORTANT: V2 failure does NOT fall back to V1.
    Each version loads and fails independently.
    """
    global _clf_cache, _le_cache, _v2_clf_cache, _v2_le_cache

    if version == 'v2':
        if _v2_clf_cache is not None:
            return _v2_clf_cache, _v2_le_cache
        if not os.path.exists(_MODEL_PATH_V2):
            logger.info("No V2 model found at %s", _MODEL_PATH_V2)
            return None, None
        try:
            import joblib
            bundle = joblib.load(_MODEL_PATH_V2)
            _v2_clf_cache = bundle['model']
            _v2_le_cache  = bundle['label_encoder']
            logger.info("Loaded V2 traffic classifier from %s", _MODEL_PATH_V2)
            return _v2_clf_cache, _v2_le_cache
        except Exception as e:
            logger.warning("Failed to load V2 model from %s: %s", _MODEL_PATH_V2, e)
            return None, None
    else:
        # V1 (default)
        if _clf_cache is not None:
            return _clf_cache, _le_cache
        if not os.path.exists(_MODEL_PATH):
            logger.info("No trained model found at %s", _MODEL_PATH)
            return None, None
        try:
            import joblib
            bundle = joblib.load(_MODEL_PATH)
            _clf_cache = bundle['model']
            _le_cache  = bundle['label_encoder']
            logger.info("Loaded traffic classifier from %s", _MODEL_PATH)
            return _clf_cache, _le_cache
        except Exception as e:
            logger.warning("Failed to load model from %s: %s", _MODEL_PATH, e)
            return None, None


# ── Inference ─────────────────────────────────────────────────────────────────

def predict_traffic_category(pcap_results: dict) -> dict:
    """
    Predict traffic category from extracted PCAP metrics.

    Uses flow-level statistical features (IAT stats, byte/packet counts)
    computed by the analyzer's packet loop.

    If the model is unavailable or features cannot be extracted, returns
    the appropriate fallback status without fabricating a result.
    """
    protocols    = pcap_results.get("protocols_found", [])
    packet_count = pcap_results.get("packet_count", 0)
    ike_version  = pcap_results.get("ike_version", "Unknown")
    flow_features = pcap_results.get("flow_features")  # dict or None

    # ── Build human-readable feature availability list ─────────────────────
    available_features = []
    if protocols:
        available_features.append(f"Protocol list: {', '.join(protocols)}")
    if packet_count > 0:
        available_features.append(f"Packet count: {packet_count}")
    if ike_version not in ("Unknown", "Not Extracted", "", None):
        available_features.append(f"IKE version: {ike_version}")

    # ── Check for ESP (classification only meaningful for ESP flows) ───────
    has_esp = "ESP" in protocols

    if not has_esp:
        return {
            "predicted_category": "Not Applicable",
            "confidence_score": None,
            "model_status": "not_applicable",
            "model_note": (
                "Traffic classification applies to ESP-encrypted data flows. "
                "No ESP packets were detected in this capture — only IKE "
                "negotiation traffic is present. Category classification "
                "is not meaningful without an encrypted data payload."
            ),
            "features_available": available_features,
            "features_required_missing": [],
            "dataset_note": (
                "Classifier trained on VNAT dataset (MIT Lincoln Laboratory). "
                "Predicts traffic category: C2, CHAT, FILE_TRANSFER, STREAMING, VOIP."
            ),
        }

    # ── Select feature schema and model based on MODEL_VERSION ──────────────
    _active_version  = _MODEL_VERSION   # module-level constant, set at import
    _active_features = _V2_FEATURE_COLS if _active_version == 'v2' else _FEATURE_COLS
    _model_file_name = ('traffic_classifier_v2.joblib'
                        if _active_version == 'v2'
                        else 'traffic_classifier.joblib')
    _retrain_script  = ('backend/models/train_classifier_v2.py'
                        if _active_version == 'v2'
                        else 'backend/models/train_classifier.py')

    # ── Try to load the trained model ──────────────────────────────────────
    clf, le = _load_model(_active_version)

    if clf is None:
        return {
            "predicted_category": "Unknown",
            "confidence_score": None,
            "model_status": "model_unavailable",
            "model_note": (
                f"No trained classifier found (MODEL_VERSION={_active_version}). "
                f"The model file ({_model_file_name}) was not found at the "
                f"expected path. Re-run {_retrain_script} to train."
            ),
            "features_available": available_features,
            "features_required_missing": _active_features,
            "model_version": _active_version,
        }

    # ── Check if flow features were extracted ──────────────────────────────
    if flow_features is None:
        return {
            "predicted_category": "Unknown",
            "confidence_score": None,
            "model_status": "insufficient_features",
            "model_note": (
                "Flow-level features were not extracted from this capture. "
                "This may occur if the capture has no valid packet timestamps."
            ),
            "features_available": available_features,
            "features_required_missing": _active_features,
            "model_version": _active_version,
        }

    # ── Build feature vector ───────────────────────────────────────────────
    missing_features = [f for f in _active_features if f not in flow_features]
    if missing_features:
        return {
            "predicted_category": "Unknown",
            "confidence_score": None,
            "model_status": "insufficient_features",
            "model_note": (
                f"Missing required flow features: {', '.join(missing_features)}. "
                "Cannot run classifier."
            ),
            "features_available": available_features,
            "features_required_missing": missing_features,
            "model_version": _active_version,
        }

    # ── Validate feature values (no NaN/Inf) ──────────────────────────────
    import math
    feature_vector = []
    bad_features = []
    for col in _active_features:
        val = flow_features[col]
        if val is None or (isinstance(val, float) and (math.isnan(val) or math.isinf(val))):
            bad_features.append(col)
            feature_vector.append(0.0)
        else:
            feature_vector.append(float(val))

    if bad_features:
        logger.warning("Invalid (NaN/Inf) feature values for: %s; replaced with 0", bad_features)

    # ── Run inference ──────────────────────────────────────────────────────
    try:
        import numpy as np
        X = np.array(feature_vector).reshape(1, -1)
        pred_enc   = clf.predict(X)[0]
        pred_proba = clf.predict_proba(X)[0]

        predicted_label      = le.inverse_transform([pred_enc])[0]
        confidence_score     = round(float(np.max(pred_proba)), 4)
        all_class_proba      = {
            cls: round(float(p), 4)
            for cls, p in zip(le.classes_, pred_proba)
        }

    except Exception as e:
        logger.error("Inference failed: %s", e)
        return {
            "predicted_category": "Unknown",
            "confidence_score": None,
            "model_status": "inference_error",
            "model_note": f"Classifier inference failed: {e}",
            "features_available": available_features,
            "features_required_missing": [],
            "model_version": _active_version,
        }

    # ── Add feature availability summary for the UI ────────────────────────
    available_features = available_features + [
        f"Flow duration: {flow_features.get('flow_duration_seconds', 0):.3f}s",
        f"Total bytes: {flow_features.get('total_bytes', 0):,}",
        f"Flow IAT mean: {flow_features.get('flow_iat_mean', 0):.4f}s",
        f"Bytes/sec (log): {flow_features.get('log_bytes_per_sec', 0):.2f}",
    ]

    # ── Low-confidence warning ─────────────────────────────────────────────
    # Short captures produce unreliable IAT statistics; warn accordingly
    is_short_capture = packet_count < 50
    model_note = (
        "Classifier trained on VNAT dataset (MIT Lincoln Laboratory). "
        f"Predicted category: {predicted_label} with {confidence_score*100:.1f}% confidence. "
        "Note: This predicts traffic TYPE (C2/Chat/Streaming/etc.), not VPN vs non-VPN. "
        "VPN/non-VPN binary detection requires the 32 GB PCAP archive not downloaded here."
    )
    if is_short_capture:
        model_note += (
            f" CAUTION: Only {packet_count} packets captured. "
            "IAT-based features have high variance in short captures; "
            "treat this prediction as indicative only."
        )

    _accuracy_note = (
        "98.76% (held-out VNAT test split, deduped, 11 features)"
        if _active_version == 'v2'
        else "98.74% (held-out VNAT test split, 17 features)"
    )

    return {
        "predicted_category": predicted_label,
        "confidence_score": confidence_score,
        "model_status": "trained_model",
        "model_note": model_note,
        "features_available": available_features,
        "features_required_missing": [],
        "all_class_probabilities": all_class_proba,
        "model_version": _active_version,
        "dataset_note": (
            f"Model: RandomForestClassifier (500 trees, {_active_version.upper()}), "
            "trained on VNAT Feature Dataframe (MIT Lincoln Laboratory). "
            f"VNAT test-set accuracy: {_accuracy_note}. "
            "Note: held-out VNAT accuracy does not guarantee real-world PCAP accuracy."
        ),
    }
