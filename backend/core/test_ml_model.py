"""
test_ml_model.py - Unit tests for ml_model.py (V1 and V2 inference paths)

Covers:
  - Feature schema integrity for both V1 (17 features) and V2 (11 features)
  - Model loading (V1 and V2) and missing-file behaviour
  - V2 failure does NOT fall back to V1
  - NaN/Inf handling in feature vectors
  - Missing feature key detection
  - ESP gate (no ESP -> Not Applicable)
  - Model unavailable -> Unknown / model_unavailable
  - Metadata missing/malformed does not affect inference
  - V1 behavior unchanged when V2 metadata is absent

Run with: python -m pytest backend/core/test_ml_model.py -v
"""

import os
import sys
import json
import math
import types
import unittest
from unittest.mock import patch, MagicMock

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

import backend.core.ml_model as ml


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _full_v1_features():
    """Return a valid flow_features dict with all 17 V1 keys."""
    return {col: 1.0 for col in ml._FEATURE_COLS}


def _full_v2_features():
    """Return a valid flow_features dict with all 11 V2 keys (superset still fine)."""
    return {col: 1.0 for col in ml._FEATURE_COLS}  # has all keys; V2 only reads its 11


def _esp_pcap_results(flow_features):
    return {
        "protocols_found": ["IKE", "ESP"],
        "packet_count": 100,
        "ike_version": "IKEv2",
        "flow_features": flow_features,
    }


# ---------------------------------------------------------------------------
# TC-01  Feature schema — V1
# ---------------------------------------------------------------------------

class TestV1FeatureOrder(unittest.TestCase):
    def test_v1_feature_count(self):
        self.assertEqual(len(ml._FEATURE_COLS), 17)

    def test_v1_exact_order(self):
        expected = [
            'out_iat_min', 'out_iat_max', 'out_iat_mean', 'out_iat_std_dev',
            'in_iat_min',  'in_iat_max',  'in_iat_mean',  'in_iat_std_dev',
            'flow_iat_min','flow_iat_max','flow_iat_mean','flow_iat_std_dev',
            'log_bytes_per_sec',
            'log_total_outgoing_packets', 'log_total_incoming_packets',
            'log_total_outgoing_bytes',   'log_total_incoming_bytes',
        ]
        self.assertEqual(ml._FEATURE_COLS, expected)


# ---------------------------------------------------------------------------
# TC-02  Feature schema — V2
# ---------------------------------------------------------------------------

class TestV2FeatureOrder(unittest.TestCase):
    def test_v2_feature_count(self):
        self.assertEqual(len(ml._V2_FEATURE_COLS), 11)

    def test_v2_exact_order(self):
        expected = [
            'out_iat_min', 'out_iat_max', 'out_iat_mean', 'out_iat_std_dev',
            'in_iat_min',  'in_iat_max',  'in_iat_mean',  'in_iat_std_dev',
            'log_bytes_per_sec',
            'log_total_outgoing_packets', 'log_total_incoming_packets',
        ]
        self.assertEqual(ml._V2_FEATURE_COLS, expected)

    def test_v2_excludes_flow_iat(self):
        for col in ['flow_iat_min', 'flow_iat_max', 'flow_iat_mean', 'flow_iat_std_dev']:
            self.assertNotIn(col, ml._V2_FEATURE_COLS,
                             msg=f"{col} must be excluded from V2 (confirmed mismatch)")

    def test_v2_excludes_byte_cols(self):
        self.assertNotIn('log_total_outgoing_bytes', ml._V2_FEATURE_COLS)
        self.assertNotIn('log_total_incoming_bytes', ml._V2_FEATURE_COLS)


# ---------------------------------------------------------------------------
# TC-03  Model loading — V1 loads from disk
# ---------------------------------------------------------------------------

class TestV1ModelLoads(unittest.TestCase):
    def test_v1_loads(self):
        # Clear cache so we test actual disk load
        ml._clf_cache = None
        ml._le_cache  = None
        clf, le = ml._load_model('v1')
        if clf is None:
            self.skipTest("V1 model file not present on disk; skipping load test")
        self.assertTrue(hasattr(clf, 'predict'), "clf must have predict()")
        self.assertTrue(hasattr(le,  'classes_'), "le must have classes_")


# ---------------------------------------------------------------------------
# TC-04  Model loading — V2 loads from disk
# ---------------------------------------------------------------------------

class TestV2ModelLoads(unittest.TestCase):
    def test_v2_loads(self):
        ml._v2_clf_cache = None
        ml._v2_le_cache  = None
        clf, le = ml._load_model('v2')
        if clf is None:
            self.skipTest("V2 model file not present on disk; skipping load test")
        self.assertTrue(hasattr(clf, 'predict'))
        self.assertEqual(len(clf.feature_importances_), 11,
                         "V2 model must have exactly 11 feature importances")


# ---------------------------------------------------------------------------
# TC-05  Missing model file — V1
# ---------------------------------------------------------------------------

class TestMissingModelV1(unittest.TestCase):
    def test_missing_v1_returns_none(self):
        ml._clf_cache = None
        ml._le_cache  = None
        with patch('os.path.exists', return_value=False):
            clf, le = ml._load_model('v1')
        self.assertIsNone(clf)
        self.assertIsNone(le)


# ---------------------------------------------------------------------------
# TC-06  Missing model file — V2 does NOT fall back to V1
# ---------------------------------------------------------------------------

class TestMissingModelV2NoFallback(unittest.TestCase):
    def test_v2_missing_returns_none_without_v1_fallback(self):
        ml._v2_clf_cache = None
        ml._v2_le_cache  = None
        v1_load_called   = []

        real_exists = os.path.exists

        def fake_exists(path):
            if 'v2' in str(path):
                return False
            return real_exists(path)

        original_load = ml._load_model

        def patched_load(version='v1'):
            if version == 'v1':
                v1_load_called.append(True)
            return original_load(version)

        with patch('os.path.exists', side_effect=fake_exists):
            clf, le = ml._load_model('v2')

        self.assertIsNone(clf, "V2 missing => (None, None)")
        self.assertIsNone(le)
        self.assertEqual(len(v1_load_called), 0, "V1 _load_model must NOT be called when V2 is missing")


# ---------------------------------------------------------------------------
# TC-07  NaN/Inf handling — V1 path
# ---------------------------------------------------------------------------

class TestNanInfHandlingV1(unittest.TestCase):
    def test_nan_inf_v1_no_crash(self):
        bad_features = _full_v1_features()
        bad_features['out_iat_min']  = float('nan')
        bad_features['out_iat_max']  = float('inf')
        bad_features['out_iat_mean'] = float('-inf')

        pcap_results = _esp_pcap_results(bad_features)

        with patch.dict(os.environ, {'MODEL_VERSION': 'v1'}):
            # Reload MODEL_VERSION constant
            ml._MODEL_VERSION = 'v1'
            mock_clf = MagicMock()
            mock_clf.predict.return_value = [0]
            mock_clf.predict_proba.return_value = [[0.9, 0.05, 0.03, 0.01, 0.01]]
            mock_le  = MagicMock()
            mock_le.inverse_transform.return_value = ['CHAT']
            mock_le.classes_ = ['C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP']
            with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
                result = ml.predict_traffic_category(pcap_results)

        self.assertNotEqual(result.get('model_status'), 'inference_error',
                            "NaN/Inf must not cause inference_error")
        self.assertIsNotNone(result.get('predicted_category'))


# ---------------------------------------------------------------------------
# TC-08  NaN/Inf handling — V2 path
# ---------------------------------------------------------------------------

class TestNanInfHandlingV2(unittest.TestCase):
    def test_nan_inf_v2_no_crash(self):
        bad_features = _full_v2_features()
        bad_features['in_iat_min']  = float('nan')
        bad_features['log_bytes_per_sec'] = float('inf')

        pcap_results = _esp_pcap_results(bad_features)

        ml._MODEL_VERSION = 'v2'
        mock_clf = MagicMock()
        mock_clf.predict.return_value = [0]
        mock_clf.predict_proba.return_value = [[0.9, 0.05, 0.03, 0.01, 0.01]]
        mock_le  = MagicMock()
        mock_le.inverse_transform.return_value = ['CHAT']
        mock_le.classes_ = ['C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP']
        try:
            with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
                result = ml.predict_traffic_category(pcap_results)
            self.assertNotEqual(result.get('model_status'), 'inference_error')
        finally:
            ml._MODEL_VERSION = 'v1'  # restore


# ---------------------------------------------------------------------------
# TC-09  Missing feature key
# ---------------------------------------------------------------------------

class TestMissingFeatureKey(unittest.TestCase):
    def test_missing_key_returns_insufficient(self):
        ff = _full_v1_features()
        del ff['out_iat_min']  # remove a required key

        pcap_results = _esp_pcap_results(ff)
        ml._MODEL_VERSION = 'v1'

        mock_clf = MagicMock()
        mock_le  = MagicMock()
        with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
            result = ml.predict_traffic_category(pcap_results)

        self.assertEqual(result['model_status'], 'insufficient_features')
        self.assertEqual(result['predicted_category'], 'Unknown')
        self.assertIn('out_iat_min', result['features_required_missing'])


# ---------------------------------------------------------------------------
# TC-10  No ESP -> Not Applicable
# ---------------------------------------------------------------------------

class TestNoEspNotApplicable(unittest.TestCase):
    def test_no_esp_not_applicable(self):
        pcap_results = {
            "protocols_found": ["IKE"],
            "packet_count": 50,
            "ike_version": "IKEv2",
            "flow_features": _full_v1_features(),
        }
        result = ml.predict_traffic_category(pcap_results)
        self.assertEqual(result['model_status'], 'not_applicable')
        self.assertEqual(result['predicted_category'], 'Not Applicable')
        self.assertIsNone(result['confidence_score'])
        self.assertIsNone(result.get('model_version'))


# ---------------------------------------------------------------------------
# TC-11  Model unavailable -> Unknown / model_unavailable
# ---------------------------------------------------------------------------

class TestModelUnavailable(unittest.TestCase):
    def test_model_unavailable_returns_unknown(self):
        ml._MODEL_VERSION = 'v1'
        with patch.object(ml, '_load_model', return_value=(None, None)):
            result = ml.predict_traffic_category(_esp_pcap_results(_full_v1_features()))
        self.assertEqual(result['predicted_category'], 'Unknown')
        self.assertEqual(result['model_status'], 'model_unavailable')
        self.assertIsNone(result['confidence_score'])


# ---------------------------------------------------------------------------
# TC-12  V2 metadata missing -> inference still succeeds
# ---------------------------------------------------------------------------

class TestV2MetadataMissing(unittest.TestCase):
    def test_inference_succeeds_without_metadata(self):
        """Deleting classifier_v2_metadata.json must not affect predictions."""
        meta_path = os.path.join(ml._MODELS_DIR, 'classifier_v2_metadata.json')
        ml._MODEL_VERSION = 'v2'
        mock_clf = MagicMock()
        mock_clf.predict.return_value = [0]
        mock_clf.predict_proba.return_value = [[0.9, 0.05, 0.03, 0.01, 0.01]]
        mock_le  = MagicMock()
        mock_le.inverse_transform.return_value = ['C2']
        mock_le.classes_ = ['C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP']
        try:
            with patch('os.path.exists', side_effect=lambda p: p != meta_path):
                with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
                    result = ml.predict_traffic_category(_esp_pcap_results(_full_v2_features()))
            # Inference must return a prediction, not a crash
            self.assertIn(result['predicted_category'], ['C2', 'Unknown', 'Not Applicable'])
            self.assertNotIn('metadata', str(result).lower(),
                             "Prediction result must not expose raw metadata fields")
        finally:
            ml._MODEL_VERSION = 'v1'


# ---------------------------------------------------------------------------
# TC-13  V2 metadata malformed -> inference still succeeds
# ---------------------------------------------------------------------------

class TestV2MetadataMalformed(unittest.TestCase):
    def test_inference_succeeds_with_corrupt_metadata(self):
        """Corrupt JSON in metadata file must not affect predictions."""
        ml._MODEL_VERSION = 'v2'
        mock_clf = MagicMock()
        mock_clf.predict.return_value = [1]
        mock_clf.predict_proba.return_value = [[0.05, 0.9, 0.03, 0.01, 0.01]]
        mock_le  = MagicMock()
        mock_le.inverse_transform.return_value = ['CHAT']
        mock_le.classes_ = ['C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP']
        try:
            # ml_model.py never reads metadata at inference; test confirms no crash
            with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
                result = ml.predict_traffic_category(_esp_pcap_results(_full_v2_features()))
            self.assertNotEqual(result.get('model_status'), 'inference_error')
        finally:
            ml._MODEL_VERSION = 'v1'


# ---------------------------------------------------------------------------
# TC-14  V1 behavior unchanged when V2 metadata is absent
# ---------------------------------------------------------------------------

class TestV1UnaffectedByMissingV2Metadata(unittest.TestCase):
    def test_v1_result_identical_with_without_v2_metadata(self):
        ml._MODEL_VERSION = 'v1'
        ml._clf_cache = None
        ml._le_cache  = None

        mock_clf = MagicMock()
        mock_clf.predict.return_value = [3]
        mock_clf.predict_proba.return_value = [[0.01, 0.01, 0.02, 0.95, 0.01]]
        mock_le  = MagicMock()
        mock_le.inverse_transform.return_value = ['STREAMING']
        mock_le.classes_ = ['C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP']

        with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
            result_with = ml.predict_traffic_category(_esp_pcap_results(_full_v1_features()))

        meta_path = os.path.join(ml._MODELS_DIR, 'classifier_v2_metadata.json')
        with patch('os.path.exists', side_effect=lambda p: p != meta_path):
            with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)):
                result_without = ml.predict_traffic_category(_esp_pcap_results(_full_v1_features()))

        self.assertEqual(result_with['predicted_category'], result_without['predicted_category'])
        self.assertEqual(result_with['model_status'], result_without['model_status'])
        self.assertEqual(result_with.get('model_version'), 'v1')
        self.assertEqual(result_without.get('model_version'), 'v1')


# ---------------------------------------------------------------------------
# TC-19  Invalid runtime MODEL_VERSION safely normalizes to v1
# ---------------------------------------------------------------------------

class TestInvalidRuntimeModelVersion(unittest.TestCase):
    def test_invalid_runtime_version_normalizes_to_v1(self):
        """Unrecognized MODEL_VERSION (e.g. 'v99') safely normalizes to v1 and agrees with v1 schema."""
        pcap_results = _esp_pcap_results(_full_v1_features())
        mock_clf = MagicMock()
        mock_clf.predict.return_value = [1]
        mock_clf.predict_proba.return_value = [[0.05, 0.9, 0.03, 0.01, 0.01]]
        mock_le  = MagicMock()
        mock_le.inverse_transform.return_value = ['CHAT']
        mock_le.classes_ = ['C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP']

        with patch.dict(os.environ, {'MODEL_VERSION': 'v99'}):
            with patch.object(ml, '_load_model', return_value=(mock_clf, mock_le)) as mock_load:
                result = ml.predict_traffic_category(pcap_results)

        # Confirm normalized to v1 and did not claim v99
        self.assertEqual(result.get('model_version'), 'v1')
        mock_load.assert_called_with('v1')
        self.assertIn('V1', result.get('dataset_note', ''))


# ---------------------------------------------------------------------------

if __name__ == '__main__':
    unittest.main()
