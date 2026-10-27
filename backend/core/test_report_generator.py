"""
test_report_generator.py — Unit tests for PDF Report Generator and Version-Aware Metadata.

Verifies:
  - Authoritative explicit model_version ('v1' and 'v2') regardless of dataset_note text
  - Conflicting metadata resolution:
      * explicit V1 with note mentioning V2 -> V1
      * explicit V2 with note mentioning V1 -> V2
  - Safe handling of missing/unknown versions:
      * missing version with misleading V2 note -> unknown (never V2)
      * missing version with arbitrary note -> unknown
  - Verified exact legacy V1 signatures from historical database records -> V1 (legacy)
  - Full PDF generation for V1, V2, missing-version, and not-applicable ML scenarios
"""

import unittest
from backend.core.report_generator import _resolve_model_metadata, generate_pdf


class TestModelMetadataResolution(unittest.TestCase):
    """Test _resolve_model_metadata logic adhering to validation principles."""

    def test_v1_explicit_metadata(self):
        ml = {
            "model_version": "v1",
            "model_status": "trained_model",
            "predicted_category": "CHAT",
            "confidence_score": 0.95,
            "dataset_note": "Model: RandomForestClassifier (500 trees, V1)...",
        }
        meta = _resolve_model_metadata(ml)
        self.assertEqual(meta["version"], "v1")
        self.assertIn("V1 (17 features)", meta["version_display"])
        self.assertIn("V1", meta["model_name"])
        self.assertIn("98.74%", meta["accuracy_display"])
        self.assertIn("held-out VNAT test-set accuracy", meta["accuracy_display"])
        self.assertIn("not real-world PCAP accuracy", meta["accuracy_display"])

    def test_v2_explicit_metadata(self):
        ml = {
            "model_version": "v2",
            "model_status": "trained_model",
            "predicted_category": "STREAMING",
            "confidence_score": 0.92,
            "dataset_note": "Model: RandomForestClassifier (500 trees, V2)...",
        }
        meta = _resolve_model_metadata(ml)
        self.assertEqual(meta["version"], "v2")
        self.assertIn("V2 (11 verified features)", meta["version_display"])
        self.assertIn("V2", meta["model_name"])
        self.assertIn("98.76%", meta["accuracy_display"])
        self.assertIn("held-out VNAT test-set accuracy", meta["accuracy_display"])
        self.assertIn("not real-world PCAP accuracy", meta["accuracy_display"])

    def test_explicit_v1_with_misleading_v2_note_resolves_to_v1(self):
        """Explicit model_version='v1' must win even if dataset_note mentions V2."""
        ml = {
            "model_version": "v1",
            "model_status": "trained_model",
            "predicted_category": "CHAT",
            "confidence_score": 0.85,
            "dataset_note": "Model: RandomForestClassifier evaluated against V2 metrics.",
        }
        meta = _resolve_model_metadata(ml)
        self.assertEqual(meta["version"], "v1")
        self.assertIn("V1 (17 features)", meta["version_display"])
        self.assertIn("98.74%", meta["accuracy_display"])

    def test_explicit_v2_with_misleading_v1_note_resolves_to_v2(self):
        """Explicit model_version='v2' must win even if dataset_note mentions V1."""
        ml = {
            "model_version": "v2",
            "model_status": "trained_model",
            "predicted_category": "STREAMING",
            "confidence_score": 0.90,
            "dataset_note": "Model: RandomForestClassifier (replaces previous V1 17-feature model).",
        }
        meta = _resolve_model_metadata(ml)
        self.assertEqual(meta["version"], "v2")
        self.assertIn("V2 (11 verified features)", meta["version_display"])
        self.assertIn("98.76%", meta["accuracy_display"])

    def test_missing_version_with_misleading_v2_note_never_resolves_to_v2(self):
        """Missing version must NEVER guess V2 from a dataset_note containing 'v2'."""
        ml = {
            "model_status": "trained_model",
            "predicted_category": "C2",
            "confidence_score": 0.60,
            "dataset_note": "Trained on V1 baseline; compared with V2 metrics.",
        }
        meta = _resolve_model_metadata(ml)
        self.assertNotEqual(meta["version"], "v2")
        self.assertEqual(meta["version"], "unknown")
        self.assertIn("Unknown", meta["version_display"])

    def test_missing_version_with_arbitrary_note_resolves_to_unknown(self):
        """Missing version with arbitrary text must not guess V1 or V2."""
        ml = {
            "model_status": "trained_model",
            "predicted_category": "VOIP",
            "confidence_score": 0.75,
            "dataset_note": "Captured on testbed router using custom parameters.",
        }
        meta = _resolve_model_metadata(ml)
        self.assertNotEqual(meta["version"], "v2")
        self.assertNotEqual(meta["version"], "v1")
        self.assertEqual(meta["version"], "unknown")
        self.assertIn("Unknown", meta["version_display"])

    def test_missing_version_with_exact_verified_legacy_500_signature(self):
        """Exact verified historical database signature (500 trees) resolves safely to legacy V1."""
        ml = {
            "model_status": "trained_model",
            "predicted_category": "C2",
            "confidence_score": 0.70,
            "dataset_note": "Model: RandomForestClassifier (500 trees), trained on VNAT Feature Dataframe (15,093 samples), test accuracy 98.74%.",
        }
        meta = _resolve_model_metadata(ml)
        self.assertEqual(meta["version"], "v1")
        self.assertIn("V1 (17 features, legacy record)", meta["version_display"])
        self.assertIn("98.74%", meta["accuracy_display"])

    def test_missing_version_with_exact_verified_legacy_200_signature(self):
        """Exact verified historical database signature (200 trees) resolves safely to legacy V1."""
        ml = {
            "model_status": "trained_model",
            "predicted_category": "CHAT",
            "confidence_score": 0.80,
            "dataset_note": "Model: RandomForestClassifier (200 trees), trained on VNAT Feature Dataframe (15,093 samples), test accuracy 98.48%.",
        }
        meta = _resolve_model_metadata(ml)
        self.assertEqual(meta["version"], "v1")
        self.assertIn("V1 (17 features, legacy record)", meta["version_display"])
        self.assertIn("200 trees", meta["model_name"])
        self.assertIn("98.48%", meta["accuracy_display"])

    def test_missing_version_and_empty_note_never_labels_as_v2(self):
        """Completely missing metadata must resolve to unknown and never label as V2."""
        ml = {
            "model_status": "trained_model",
            "predicted_category": "VOIP",
            "confidence_score": 0.88,
        }
        meta = _resolve_model_metadata(ml)
        self.assertNotEqual(meta["version"], "v2")
        self.assertEqual(meta["version"], "unknown")
        self.assertIn("Unknown", meta["version_display"])

    def test_unknown_version_string_never_labels_as_v2(self):
        """Unrecognized version strings must safely fall back without labeling as V2."""
        ml = {
            "model_version": "experimental_v99",
            "model_status": "trained_model",
            "predicted_category": "CHAT",
        }
        meta = _resolve_model_metadata(ml)
        self.assertNotEqual(meta["version"], "v2")
        self.assertEqual(meta["version"], "unknown")
        self.assertIn("Unknown", meta["version_display"])


class TestPdfReportGeneration(unittest.TestCase):
    """Test full PDF generation with various ML metadata payloads."""

    def _base_report(self, ml_dict):
        return {
            "id": "12345678-abcd-ef01-2345-6789abcdef01",
            "filename": "test_sample.pcap",
            "pcap_metrics": {
                "packet_count": 150,
                "ike_version": "IKEv2",
                "protocols_found": ["IKE", "ESP"],
                "vpn_mode_inferred": "Tunnel",
                "encryption": "AES-CBC",
                "key_exchange": "Group 14",
                "authentication": "PSK",
            },
            "security_assessment": {
                "overall_risk_score": 0,
                "risk_level": "Informational",
                "score_explanation": "Clean capture.",
                "findings": [],
                "rules_evaluated": [
                    {"rule": "IKE Version", "observed_value": "IKEv2", "status": "PASS"},
                ],
                "rules_skipped": [],
            },
            "ml_prediction": ml_dict,
        }

    def test_generate_pdf_v1(self):
        ml = {
            "model_version": "v1",
            "model_status": "trained_model",
            "predicted_category": "CHAT",
            "confidence_score": 0.88,
            "dataset_note": "Model: RandomForestClassifier (500 trees, V1)...",
            "all_class_probabilities": {"CHAT": 0.88, "C2": 0.05, "STREAMING": 0.05, "FILE_TRANSFER": 0.01, "VOIP": 0.01},
            "features_available": ["Flow duration: 5.0s", "Total bytes: 10,000"],
        }
        pdf = generate_pdf(self._base_report(ml))
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertTrue(len(pdf) > 1000)

    def test_generate_pdf_v2(self):
        ml = {
            "model_version": "v2",
            "model_status": "trained_model",
            "predicted_category": "STREAMING",
            "confidence_score": 0.94,
            "dataset_note": "Model: RandomForestClassifier (500 trees, V2)...",
            "all_class_probabilities": {"STREAMING": 0.94, "CHAT": 0.03, "C2": 0.02, "FILE_TRANSFER": 0.01, "VOIP": 0.0},
            "features_available": ["Flow duration: 12.0s", "Total bytes: 50,000"],
        }
        pdf = generate_pdf(self._base_report(ml))
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertTrue(len(pdf) > 1000)

    def test_generate_pdf_missing_version(self):
        """Missing version must still generate a valid PDF report."""
        ml = {
            "model_status": "trained_model",
            "predicted_category": "C2",
            "confidence_score": 0.65,
        }
        pdf = generate_pdf(self._base_report(ml))
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_generate_pdf_not_applicable(self):
        """Not applicable ML status must generate valid PDF report without inventing a version."""
        ml = {
            "model_status": "not_applicable",
            "predicted_category": "Not Applicable",
            "model_note": "No ESP packets detected in capture.",
            "model_version": None,
        }
        pdf = generate_pdf(self._base_report(ml))
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
