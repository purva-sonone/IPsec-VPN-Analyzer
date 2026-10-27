import os
import sys
import unittest

# Ensure backend/core is in sys.path whether executed from root, backend, or backend/core
_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from security_rules import evaluate_security

class TestSecurityRules(unittest.TestCase):
    def test_weak_dh_group(self):
        pcap_results = {
            "key_exchange": "Alternate 1024-bit MODP group"
        }
        res = evaluate_security(pcap_results)
        
        # Should have high finding and +3 risk
        self.assertEqual(res["overall_risk_score"], 3)
        self.assertTrue(any(f["title"] == "Weak Diffie-Hellman Group" for f in res["findings"]))
        
        # Rule Audit should be FAIL
        dh_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "Diffie-Hellman Group Strength"), None)
        self.assertIsNotNone(dh_rule)
        self.assertEqual(dh_rule["status"], "FAIL")

    def test_adequate_dh_group(self):
        pcap_results = {
            "key_exchange": "Group 19 (ECP-256)"
        }
        res = evaluate_security(pcap_results)
        
        # Should have no risk from DH group
        self.assertEqual(res["overall_risk_score"], 0)
        self.assertTrue(any(f["title"] == "Adequate Diffie-Hellman Group" for f in res["findings"]))
        
        # Rule Audit should be PASS
        dh_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "Diffie-Hellman Group Strength"), None)
        self.assertIsNotNone(dh_rule)
        self.assertEqual(dh_rule["status"], "PASS")

    def test_missing_dh_group(self):
        pcap_results = {
            "key_exchange": "Not Extracted"
        }
        res = evaluate_security(pcap_results)
        
        # Rule should be in rules_skipped
        self.assertTrue(any(r["rule"] == "Diffie-Hellman Group Strength" for r in res["rules_skipped"]))
        
        # Rule should not be in rules_evaluated
        dh_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "Diffie-Hellman Group Strength"), None)
        self.assertIsNone(dh_rule)

    def test_esp_payload_protection_pass(self):
        pcap_results = {
            "protocols_found": ["IKE", "ESP"],
            "vpn_mode_inferred": "Tunnel",
        }
        res = evaluate_security(pcap_results)
        esp_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "ESP Payload Protection"), None)
        self.assertIsNotNone(esp_rule)
        self.assertEqual(esp_rule["status"], "PASS")
        self.assertEqual(esp_rule["observed_value"], "ESP Encapsulation Present")

    def test_esp_control_only_not_observed(self):
        pcap_results = {
            "protocols_found": ["IKE"],
        }
        res = evaluate_security(pcap_results)
        esp_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "ESP Payload Protection"), None)
        self.assertIsNotNone(esp_rule)
        self.assertEqual(esp_rule["status"], "NOT OBSERVED")
        self.assertEqual(esp_rule["observed_value"], "No ESP Packets Observed")

    def test_ikev1_recommendation_wording(self):
        pcap_results = {
            "ike_version": "IKEv1",
        }
        res = evaluate_security(pcap_results)
        finding = next((f for f in res["findings"] if f["title"] == "IKEv1 Detected"), None)
        self.assertIsNotNone(finding)
        self.assertNotIn("mandatory EAP", finding["recommendation"])
        self.assertEqual(
            finding["recommendation"],
            "Migrate to IKEv2, which is more modern and secure and supports stronger authentication options such as EAP and certificates."
        )

    def test_certificate_based_authentication_title(self):
        pcap_results = {
            "authentication": "RSA Digital Signature",
        }
        res = evaluate_security(pcap_results)
        finding = next((f for f in res["findings"] if f["title"] == "Certificate-Based Authentication"), None)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["severity"], "Informational")
        self.assertNotIn("Certificate/Signature-Based", [f["title"] for f in res["findings"]])

    def test_beaconing_high_anomaly_fails(self):
        pcap_results = {
            "beaconing_analysis": {
                "status": "evaluated",
                "anomaly_score": 82.5,
                "beacon_detected": True,
                "estimated_interval_sec": 5.0,
                "jitter_sec": 0.05,
                "timing_regularity_pct": 92.0,
            }
        }
        res = evaluate_security(pcap_results)
        self.assertGreaterEqual(res["overall_risk_score"], 3)
        self.assertTrue(any(f["title"] == "Periodic Beaconing Activity Detected" for f in res["findings"]))
        b_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "C2 Beaconing Analysis"), None)
        self.assertIsNotNone(b_rule)
        self.assertEqual(b_rule["status"], "FAIL")

    def test_beaconing_normal_passes(self):
        pcap_results = {
            "beaconing_analysis": {
                "status": "evaluated",
                "anomaly_score": 18.0,
                "beacon_detected": False,
                "estimated_interval_sec": 0.4,
                "jitter_sec": 1.2,
                "timing_regularity_pct": 20.0,
            }
        }
        res = evaluate_security(pcap_results)
        self.assertEqual(res["overall_risk_score"], 0)
        self.assertFalse(any(f["title"] == "Periodic Beaconing Activity Detected" for f in res["findings"]))
        b_rule = next((r for r in res["rules_evaluated"] if r["rule"] == "C2 Beaconing Analysis"), None)
        self.assertIsNotNone(b_rule)
        self.assertEqual(b_rule["status"], "PASS")

    def test_beaconing_insufficient_skipped(self):
        pcap_results = {
            "beaconing_analysis": {
                "status": "insufficient_data",
                "explanation": "At least 5 packets required."
            }
        }
        res = evaluate_security(pcap_results)
        self.assertTrue(any(r["rule"] == "C2 Beaconing Analysis" for r in res["rules_skipped"]))

if __name__ == '__main__':
    unittest.main()
