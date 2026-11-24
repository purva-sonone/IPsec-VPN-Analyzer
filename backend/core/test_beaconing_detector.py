import os
import sys
import unittest

_CORE_DIR = os.path.dirname(os.path.abspath(__file__))
if _CORE_DIR not in sys.path:
    sys.path.insert(0, _CORE_DIR)

from beaconing_detector import analyze_beaconing


class TestBeaconingDetector(unittest.TestCase):
    def test_periodic_c2_beaconing(self):
        """Simulate strict 5.0s beaconing with tiny jitter and small uniform payloads."""
        base_time = 1700000000.0
        # 20 packets arriving every ~5.0s (±0.05s)
        timestamps = [base_time + (i * 5.0) + (0.02 if i % 2 == 0 else -0.02) for i in range(20)]
        sizes = [96] * 20  # uniform small probe packets

        res = analyze_beaconing(timestamps, sizes, protocols_found=["ESP"])

        self.assertEqual(res["status"], "evaluated")
        self.assertTrue(res["beacon_detected"])
        self.assertEqual(res["anomaly_level"], "HIGH")
        self.assertGreaterEqual(res["anomaly_score"], 68.0)
        self.assertAlmostEqual(res["estimated_interval_sec"], 5.0, delta=0.2)
        self.assertIn("Periodic Beaconing", res["verdict"])
        self.assertGreater(res["timing_regularity_pct"], 80.0)

    def test_human_interactive_sporadic(self):
        """Simulate sporadic human traffic (variable typing, reading pauses)."""
        base_time = 1700000000.0
        # Random bursty intervals: 0.1s, 0.05s, 4.2s, 0.2s, 15.0s, 1.1s, 0.05s, 8.5s...
        delays = [0.1, 0.05, 4.2, 0.2, 15.0, 1.1, 0.05, 8.5, 0.3, 0.1, 22.0, 0.4]
        timestamps = [base_time]
        for d in delays:
            timestamps.append(timestamps[-1] + d)
        sizes = [150, 400, 80, 1200, 300, 60, 1400, 200, 500, 70, 900, 150, 800]

        res = analyze_beaconing(timestamps, sizes, protocols_found=["ESP"])

        self.assertEqual(res["status"], "evaluated")
        self.assertFalse(res["beacon_detected"])
        self.assertEqual(res["anomaly_level"], "LOW")
        self.assertLess(res["anomaly_score"], 45.0)
        self.assertIn("Aperiodic", res["verdict"])

    def test_bulk_transfer_streaming_bursts(self):
        """Simulate high-speed bulk packets (sub-10ms intervals)."""
        base_time = 1700000000.0
        # 50 packets arriving at 0.005s intervals
        timestamps = [base_time + (i * 0.005) for i in range(50)]
        sizes = [1420] * 50

        res = analyze_beaconing(timestamps, sizes, protocols_found=["ESP"])

        self.assertEqual(res["status"], "evaluated")
        self.assertFalse(res["beacon_detected"])
        # Bulk transfer should not be falsely classified as high-risk C2 beaconing
        self.assertLess(res["anomaly_score"], 60.0)

    def test_insufficient_packets(self):
        """Fewer than 5 packets should return insufficient_data without crashing."""
        res = analyze_beaconing([1.0, 2.0, 3.0])
        self.assertEqual(res["status"], "insufficient_data")
        self.assertFalse(res["beacon_detected"])
        self.assertEqual(res["anomaly_score"], 0.0)

    def test_empty_or_none(self):
        """Empty or None lists should return insufficient_data gracefully."""
        res = analyze_beaconing([])
        self.assertEqual(res["status"], "insufficient_data")
        res_none = analyze_beaconing(None)
        self.assertEqual(res_none["status"], "insufficient_data")

    def test_simultaneous_packets(self):
        """All packets at identical timestamp."""
        res = analyze_beaconing([100.0, 100.0, 100.0, 100.0, 100.0])
        self.assertEqual(res["status"], "insufficient_data")

    def test_small_sample_synthetic_capture_not_high_risk(self):
        """A minimal 5-packet synthetic capture with fixed intervals must NOT score 100/100 or trigger High Risk."""
        base_time = 1700000000.0
        # 5 packets at exact 1.0s intervals (4 intervals, total 4.0s duration)
        timestamps = [base_time + float(i) for i in range(5)]
        sizes = [96] * 5

        res = analyze_beaconing(timestamps, sizes, protocols_found=["ESP"])

        self.assertEqual(res["status"], "evaluated")
        self.assertFalse(res["beacon_detected"])
        self.assertNotEqual(res["anomaly_score"], 100.0)
        self.assertLessEqual(res["anomaly_score"], 45.0)
        self.assertNotEqual(res["anomaly_level"], "HIGH")
        self.assertTrue(res["is_small_sample"])
        self.assertEqual(res["confidence_level"], "LOW")
        self.assertEqual(res["sample_size_intervals"], 4)
        self.assertAlmostEqual(res["observation_duration_sec"], 4.0, delta=0.1)

    def test_behavioral_indicator_wording(self):
        """Ensures verdict and insights describe periodicity as a behavioral indicator, not definitive proof of C2."""
        base_time = 1700000000.0
        # 20 packets to trigger high regularity
        timestamps = [base_time + (i * 2.0) for i in range(20)]
        sizes = [120] * 20

        res = analyze_beaconing(timestamps, sizes, protocols_found=["ESP"])

        self.assertEqual(res["status"], "evaluated")
        self.assertIn("Behavioral", res["verdict"])
        # Check insights explicitly state that timing is a behavioral indicator and mention benign keepalives
        combined_insights = " ".join(res["insights"])
        self.assertIn("behavioral indicator", combined_insights.lower())
        self.assertIn("keepalive", combined_insights.lower())

    def test_moderate_sample_size_confidence(self):
        """A 10-14 packet trace should have moderate confidence and not jump to immediate 100/100."""
        base_time = 1700000000.0
        timestamps = [base_time + (i * 3.0) for i in range(12)]

        res = analyze_beaconing(timestamps, protocols_found=["ESP"])
        self.assertEqual(res["status"], "evaluated")
        self.assertEqual(res["confidence_level"], "MODERATE")
        self.assertLess(res["anomaly_score"], 100.0)


if __name__ == '__main__':
    unittest.main()

