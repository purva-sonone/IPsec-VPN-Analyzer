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
  v1           — 17 features including flow_iat_* and byte columns.
                 traffic_classifier.joblib
  v2 (default) — 11 independently verified features; drops flow_iat_* (confirmed
                 training-inference mismatch) and byte columns (100% identical to
                 packet count columns in dataset). traffic_classifier_v2.joblib

Select version via MODEL_VERSION environment variable (default: 'v2').
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

# ── Model version selection (MODEL_VERSION env-var, default 'v2') ─────────────
# Read once at import time; restart the server to change.

_raw_model_ver = os.environ.get('MODEL_VERSION', 'v2').strip().lower()
_MODEL_VERSION = _raw_model_ver if _raw_model_ver in ('v1', 'v2') else 'v2'



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
    Invalid version strings safely normalize to 'v1'.
    """
    global _clf_cache, _le_cache, _v2_clf_cache, _v2_le_cache
    norm_ver = (version or 'v1').strip().lower()
    if norm_ver not in ('v1', 'v2'):
        logger.warning("Unrecognized model version '%s' requested; normalizing to 'v1'", version)
        norm_ver = 'v1'

    if norm_ver == 'v2':
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


# ── Feature Metadata & Explainable AI (XAI) Definitions ───────────────────────

_FEATURE_METADATA = {
    'out_iat_min': {
        'name': 'Min Outbound Interval',
        'unit': 's',
        'description': 'Smallest observed gap between consecutive outbound packets',
    },
    'out_iat_max': {
        'name': 'Max Outbound Interval',
        'unit': 's',
        'description': 'Longest pause observed between outbound transmissions',
    },
    'out_iat_mean': {
        'name': 'Mean Outbound Cadence',
        'unit': 's',
        'description': 'Average interval between outgoing packet transmissions',
    },
    'out_iat_std_dev': {
        'name': 'Outbound Timing Jitter / Regularity',
        'unit': 's',
        'description': 'Variance in outbound timing; near-zero indicates strict periodicity',
    },
    'in_iat_min': {
        'name': 'Min Inbound Interval',
        'unit': 's',
        'description': 'Smallest observed gap between consecutive inbound responses',
    },
    'in_iat_max': {
        'name': 'Max Inbound Interval',
        'unit': 's',
        'description': 'Longest pause observed between inbound responses',
    },
    'in_iat_mean': {
        'name': 'Mean Inbound Cadence',
        'unit': 's',
        'description': 'Average interval between incoming packet arrivals',
    },
    'in_iat_std_dev': {
        'name': 'Inbound Timing Jitter / Regularity',
        'unit': 's',
        'description': 'Variance in inbound timing regularity',
    },
    'log_bytes_per_sec': {
        'name': 'Throughput Density',
        'unit': 'log B/s',
        'description': 'Log-scale transfer rate indicating bandwidth consumption',
    },
    'log_total_outgoing_packets': {
        'name': 'Outbound Packet Volume',
        'unit': 'log pkts',
        'description': 'Log-scale count of client-to-gateway transmissions',
    },
    'log_total_incoming_packets': {
        'name': 'Inbound Packet Volume',
        'unit': 'log pkts',
        'description': 'Log-scale count of gateway-to-client responses',
    },
    'flow_iat_min': {
        'name': 'Min Flow Interval',
        'unit': 's',
        'description': 'Smallest interval across entire bidirectional flow',
    },
    'flow_iat_max': {
        'name': 'Max Flow Interval',
        'unit': 's',
        'description': 'Longest pause across entire bidirectional session',
    },
    'flow_iat_mean': {
        'name': 'Mean Flow Cadence',
        'unit': 's',
        'description': 'Average bidirectional packet arrival rate',
    },
    'flow_iat_std_dev': {
        'name': 'Session Timing Regularity',
        'unit': 's',
        'description': 'Overall bidirectional session timing jitter',
    },
    'log_total_outgoing_bytes': {
        'name': 'Outbound Byte Volume',
        'unit': 'log B',
        'description': 'Total outbound bytes transferred',
    },
    'log_total_incoming_bytes': {
        'name': 'Inbound Byte Volume',
        'unit': 'log B',
        'description': 'Total inbound bytes received',
    },
}


def _generate_feature_reason(category: str, feature_key: str, value: float) -> str:
    """Generate concise, domain-grounded explanation of why this feature supports the category."""
    cat = (category or "").upper()
    if cat == "C2":
        if "std_dev" in feature_key:
            return f"Low arrival jitter ({value:.4f}s) indicates automated scheduled beaconing rather than human behavior."
        elif "mean" in feature_key:
            return f"Periodic cadence (~{value:.2f}s) matches persistent implant heartbeat / callback intervals."
        elif "bytes_per_sec" in feature_key:
            return f"Low throughput density ({value:.2f}) matches lightweight heartbeat probes rather than bulk data."
        elif "packet" in feature_key:
            return f"Asymmetric flow ratio reflects automated client check-ins without heavy downstream media."
        else:
            return f"Flow timing parameter ({value:.3f}) strongly aligns with automated C2 beacon profiles."
    elif cat == "VOIP":
        if "iat" in feature_key and ("min" in feature_key or "mean" in feature_key):
            return f"Rapid, steady packet cadence (~{value:.3f}s) matches real-time bidirectional audio packetization."
        elif "std_dev" in feature_key:
            return f"Minimal timing jitter ({value:.4f}s) matches fixed-frame voice RTP audio codecs."
        elif "bytes_per_sec" in feature_key:
            return f"Steady moderate bandwidth ({value:.2f}) typical of compressed VoIP audio streams."
        else:
            return f"Symmetric low-latency characteristics typical of VoIP telephony."
    elif cat == "STREAMING":
        if "bytes_per_sec" in feature_key:
            return f"High sustained throughput density ({value:.2f}) typical of continuous multimedia bitstreams."
        elif "in_iat" in feature_key or "incoming" in feature_key:
            return f"Dense incoming packet volume matches video chunk download and media buffer replenishment."
        else:
            return f"High-volume downstream flow pattern characteristic of video/audio streaming."
    elif cat == "FILE_TRANSFER":
        if "bytes_per_sec" in feature_key or "outgoing" in feature_key or "incoming" in feature_key:
            return f"High data volume and sustained packet transfer rate typical of bulk file synchronization."
        elif "min" in feature_key:
            return f"Near-zero minimum IAT ({value:.4f}s) reflects TCP back-to-back packet burst transmission."
        else:
            return f"Bulk transfer characteristics with sustained packet delivery."
    elif cat == "CHAT":
        if "max" in feature_key or "std_dev" in feature_key:
            return f"High inter-arrival variance ({value:.2f}s) reflects sporadic human typing and reading pauses."
        elif "bytes_per_sec" in feature_key or "packet" in feature_key:
            return f"Low packet volume with minimal bandwidth consumption typical of instant messaging."
        else:
            return f"Sporadic bursts separated by conversational idle pauses characteristic of chat."
    else:
        return f"Observed feature value ({value:.3f}) provided strongest statistical attribution toward {category}."


def explain_prediction(
    clf,
    le,
    feature_names: list,
    feature_vector: list,
    pred_enc: int,
    predicted_label: str,
    confidence_score: float,
) -> dict | None:
    """
    Compute local feature attributions using exact tree decision path analysis (TreeInterpreter / Saabas).
    Identifies the top contributing factors driving the Random Forest model toward the predicted category.
    """
    try:
        import numpy as np
        x_in = np.array([feature_vector], dtype=np.float32)
        n_features = len(feature_names)
        contributions = np.zeros(n_features, dtype=np.float64)

        for tree in clf.estimators_:
            t = tree.tree_
            node_indicator = t.decision_path(x_in).toarray()[0]
            path_nodes = np.where(node_indicator == 1)[0]
            for i in range(len(path_nodes) - 1):
                curr_node = path_nodes[i]
                next_node = path_nodes[i + 1]
                feature = t.feature[curr_node]
                if feature >= 0:
                    s_curr = float(np.sum(t.value[curr_node][0]))
                    s_next = float(np.sum(t.value[next_node][0]))
                    if s_curr > 0 and s_next > 0:
                        val_curr = t.value[curr_node][0] / s_curr
                        val_next = t.value[next_node][0] / s_next
                        contributions[feature] += (val_next[pred_enc] - val_curr[pred_enc])

        n_estimators = len(clf.estimators_)
        if n_estimators > 0:
            contributions /= n_estimators

        ranked_indices = np.argsort(-contributions)
        positive_indices = [idx for idx in ranked_indices if contributions[idx] > 0]
        top_indices = positive_indices[:4] if len(positive_indices) >= 2 else ranked_indices[:3].tolist()
        total_positive = sum(contributions[i] for i in top_indices if contributions[i] > 0)

        top_factors = []
        for rank, idx in enumerate(top_indices, start=1):
            feat_key = feature_names[idx]
            feat_val = float(feature_vector[idx])
            contrib = float(contributions[idx])
            meta = _FEATURE_METADATA.get(feat_key, {
                'name': feat_key.replace('_', ' ').title(),
                'unit': '',
                'description': 'Flow statistical attribute'
            })
            unit_str = f" {meta['unit']}" if meta['unit'] else ""
            if "iat" in feat_key:
                val_fmt = f"{feat_val:.4f}s"
            elif "bytes" in feat_key or "packet" in feat_key:
                val_fmt = f"{feat_val:.2f}{unit_str}"
            else:
                val_fmt = f"{feat_val:.3f}{unit_str}"

            impact_pct = float(round((contrib / total_positive) * 100.0, 1)) if total_positive > 0 else float(round(100.0 / len(top_indices), 1))

            top_factors.append({
                "rank": rank,
                "feature_key": feat_key,
                "feature_name": meta["name"],
                "observed_value": val_fmt,
                "raw_value": round(feat_val, 4),
                "attribution_score": round(contrib, 4),
                "impact_percentage": max(1.0, float(impact_pct)),
                "reason": _generate_feature_reason(predicted_label, feat_key, feat_val),
            })

        top_names = [f["feature_name"] for f in top_factors[:2]]
        summary = (
            f"Classification as {predicted_label} was primarily driven by "
            f"{top_names[0]} and {top_names[1]} based on tree decision path analysis."
            if len(top_names) >= 2 else f"Classification driven by {top_factors[0]['feature_name']}."
        )

        return {
            "method": "Exact Tree Decision Path Attribution (TreeInterpreter / Saabas)",
            "target_category": predicted_label,
            "confidence_score": confidence_score,
            "top_contributing_factors": top_factors,
            "summary": summary,
        }
    except Exception as err:
        logger.warning("Feature attribution failed: %s", err)
        return None


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
            "model_version": None,
            "dataset_note": (
                "Classifier trained on VNAT dataset (MIT Lincoln Laboratory). "
                "Predicts traffic category: C2, CHAT, FILE_TRANSFER, STREAMING, VOIP."
            ),
            "explainability": None,
        }

    # ── Select feature schema and model based on MODEL_VERSION ──────────────
    raw_env_ver = os.environ.get('MODEL_VERSION', _MODEL_VERSION).strip().lower()
    if raw_env_ver in ('v1', 'v2'):
        _active_version = raw_env_ver
    else:
        logger.warning("Invalid MODEL_VERSION '%s'; safely normalizing to 'v1'", raw_env_ver)
        _active_version = 'v1'
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
            "explainability": None,
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
            "explainability": None,
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
            "explainability": None,
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
            "explainability": None,
        }

    # ── Add feature availability summary for the UI ────────────────────────
    available_features = available_features + [
        f"Flow duration: {flow_features.get('flow_duration_seconds', 0):.3f}s",
        f"Total bytes: {flow_features.get('total_bytes', 0):,}",
        f"Flow IAT mean: {flow_features.get('flow_iat_mean', 0):.4f}s",
        f"Bytes/sec (log): {flow_features.get('log_bytes_per_sec', 0):.2f}",
    ]

    # ── Reliability & Sample Size Indicators ──────────────────────────────
    MIN_PACKETS_THRESHOLD = 30
    MIN_CONFIDENCE_THRESHOLD = 0.65

    # Always output the actual predicted category label from the classifier
    predicted_category = predicted_label

    if packet_count < MIN_PACKETS_THRESHOLD:
        model_note = (
            f"Capture contains {packet_count} packet(s). "
            f"Predicted category: {predicted_category} with {confidence_score*100:.1f}% confidence. "
            f"Note: captures with fewer than {MIN_PACKETS_THRESHOLD} packets have limited statistical sample size."
        )
    elif confidence_score < MIN_CONFIDENCE_THRESHOLD:
        model_note = (
            f"Classifier confidence ({confidence_score*100:.1f}%) is below {MIN_CONFIDENCE_THRESHOLD*100:.0f}%. "
            f"Highest statistical match: {predicted_category}."
        )
    else:
        model_note = (
            "Classifier trained on VNAT dataset (MIT Lincoln Laboratory). "
            f"Predicted category: {predicted_category} with {confidence_score*100:.1f}% confidence. "
            "Note: ESP payload is encrypted; classification is based on flow timing and volume statistics."
        )

    _accuracy_note = (
        "98.76% (held-out VNAT test split, deduped, 11 features)"
        if _active_version == 'v2'
        else "98.74% (held-out VNAT test split, 17 features)"
    )

    explainability = explain_prediction(
        clf=clf,
        le=le,
        feature_names=_active_features,
        feature_vector=feature_vector,
        pred_enc=pred_enc,
        predicted_label=predicted_label,
        confidence_score=confidence_score,
    )

    return {
        "predicted_category": predicted_category,
        "raw_predicted_category": predicted_label,
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
        "explainability": explainability,
    }
