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
from backend.core.report_generator import (
    _resolve_model_metadata,
    _audit_status_color,
    _build_rule_audit_table,
    generate_pdf,
    GREEN,
    RED,
    AMBER,
    SLATE500,
)
from backend.core.security_rules import evaluate_security


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


class TestRuleAuditColors(unittest.TestCase):
    """
    Unit tests for Rule Audit status colors:
      - PASS = green
      - FAIL = red/orange
      - REVIEW = amber
      - NOT OBSERVED and SKIPPED = neutral grey (SLATE500)
      - 'NOT OBSERVED' must never look like a pass
    """

    def test_audit_status_color_mappings(self):
        self.assertEqual(_audit_status_color("RULE PASSED"), GREEN)
        self.assertEqual(_audit_status_color("PASS"), GREEN)
        self.assertEqual(_audit_status_color("WEAKNESS DETECTED"), RED)
        self.assertEqual(_audit_status_color("FAIL"), RED)
        self.assertEqual(_audit_status_color("HIGH"), RED)
        self.assertEqual(_audit_status_color("REVIEW"), AMBER)
        self.assertEqual(_audit_status_color("NOT OBSERVED"), SLATE500)
        self.assertEqual(_audit_status_color("SKIPPED"), SLATE500)
        self.assertEqual(_audit_status_color("UNKNOWN"), SLATE500)

        # Confirm NOT OBSERVED and SKIPPED never look like a pass or review
        self.assertNotEqual(_audit_status_color("NOT OBSERVED"), GREEN)
        self.assertNotEqual(_audit_status_color("NOT OBSERVED"), AMBER)
        self.assertNotEqual(_audit_status_color("SKIPPED"), GREEN)
        self.assertNotEqual(_audit_status_color("SKIPPED"), AMBER)

    def test_ikev1_no_esp_rule_audit_colors(self):
        """
        Verify that an IKEv1 capture with no ESP renders 'NOT OBSERVED' in neutral grey,
        NOT green, and skipped rules also render in neutral grey.
        """
        sa = evaluate_security({
            "protocols_found": ["IKE"],
            "ike_version": "IKEv1",
        })

        # Confirm security rules engine produces NOT OBSERVED for ESP
        esp_rule = next(
            (r for r in sa["rules_evaluated"] if r["rule"] == "ESP Payload Protection"),
            None
        )
        self.assertIsNotNone(esp_rule)
        self.assertEqual(esp_rule["status"], "NOT OBSERVED")

        # Build table and inspect TableStyle commands
        tbl = _build_rule_audit_table(sa["rules_evaluated"], sa["rules_skipped"])
        self.assertIsNotNone(tbl)

        commands = tbl._table_style.getCommands()
        # Find TEXTCOLOR commands on column 2 (status column)
        col2_colors = {}
        for cmd in commands:
            op = cmd[0]
            start_coord = cmd[1]
            end_coord = cmd[2]
            if op == "TEXTCOLOR" and start_coord[0] == 2 and end_coord[0] == 2:
                row_idx = start_coord[1]
                col2_colors[row_idx] = cmd[3]

        # Extract audit_data row mapping: header is row 0
        evaluated_rules = sa["rules_evaluated"]
        skipped_rules = sa["rules_skipped"]

        # Row 1 is IKE Version Check (status: FAIL / WEAKNESS DETECTED)
        ike_row = next(
            i for i, r in enumerate(evaluated_rules, start=1)
            if r["rule"] == "IKE Version Check"
        )
        self.assertEqual(col2_colors[ike_row], RED)

        # ESP Payload Protection row (status: NOT OBSERVED)
        esp_row = next(
            i for i, r in enumerate(evaluated_rules, start=1)
            if r["rule"] == "ESP Payload Protection"
        )
        self.assertEqual(col2_colors[esp_row], SLATE500)
        # CRITICAL ASSERTION: Not observed must never look like a pass
        self.assertNotEqual(col2_colors[esp_row], GREEN)
        self.assertNotEqual(col2_colors[esp_row], AMBER)

        # Skipped rules rows must also be SLATE500
        r_offset = len(evaluated_rules)
        for i in range(1, len(skipped_rules) + 1):
            skip_row = r_offset + i
            self.assertEqual(col2_colors[skip_row], SLATE500)
            self.assertNotEqual(col2_colors[skip_row], GREEN)
            self.assertNotEqual(col2_colors[skip_row], AMBER)

    def test_ikev2_with_esp_rule_audit_colors(self):
        """Verify that an IKEv2 capture with ESP renders PASS in GREEN."""
        sa = evaluate_security({
            "protocols_found": ["IKE", "ESP"],
            "ike_version": "IKEv2",
            "vpn_mode_inferred": "Tunnel",
        })

        tbl = _build_rule_audit_table(sa["rules_evaluated"], sa["rules_skipped"])
        self.assertIsNotNone(tbl)

        commands = tbl._table_style.getCommands()
        col2_colors = {}
        for cmd in commands:
            if cmd[0] == "TEXTCOLOR" and cmd[1][0] == 2:
                col2_colors[cmd[1][1]] = cmd[3]

        evaluated_rules = sa["rules_evaluated"]
        esp_row = next(
            i for i, r in enumerate(evaluated_rules, start=1)
            if r["rule"] == "ESP Payload Protection"
        )
        self.assertEqual(col2_colors[esp_row], GREEN)

        ike_row = next(
            i for i, r in enumerate(evaluated_rules, start=1)
            if r["rule"] == "IKE Version Check"
        )
        self.assertEqual(col2_colors[ike_row], GREEN)

    def test_generate_pdf_with_review_and_not_observed(self):
        """Full PDF generation with diverse rule statuses including NOT OBSERVED and REVIEW."""
        report = {
            "id": "test-audit-colors-id",
            "filename": "ikev1_no_esp.pcap",
            "pcap_metrics": {
                "packet_count": 50,
                "ike_version": "IKEv1",
                "protocols_found": ["IKE"],
                "vpn_mode_inferred": "Not Extracted",
            },
            "security_assessment": {
                "overall_risk_score": 2,
                "risk_level": "Medium",
                "score_explanation": "IKEv1 observed, no ESP traffic.",
                "findings": [],
                "rules_evaluated": [
                    {"rule": "IKE Version Check", "observed_value": "IKEv1", "status": "FAIL"},
                    {"rule": "ESP Payload Protection", "observed_value": "No ESP Packets Observed", "status": "NOT OBSERVED"},
                    {"rule": "Vendor ID Check", "observed_value": "Custom Gateway", "status": "REVIEW"},
                    {"rule": "Integrity Check", "observed_value": "SHA-256", "status": "PASS"},
                ],
                "rules_skipped": [
                    {"rule": "Diffie-Hellman Group Strength", "reason": "DH group not extractable."},
                ],
            },
            "ml_prediction": {
                "model_status": "not_applicable",
                "predicted_category": "Not Applicable",
                "model_note": "No ESP packets detected in capture.",
            },
        }
        pdf = generate_pdf(report)
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))
        self.assertTrue(len(pdf) > 1000)


if __name__ == "__main__":
    unittest.main()

