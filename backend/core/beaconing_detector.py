"""
beaconing_detector.py – Behavioral Timing & Periodic Beaconing Anomaly Detector.

Detects periodic heartbeat / beaconing activity over IPsec/ESP tunnels by analyzing
packet inter-arrival time (IAT) regularity, coefficient of variation, clustering,
and packet size uniformity.

Key differentiator for C2 detection:
Provides concrete mathematical and timing evidence for Command & Control (C2)
behavior even when ESP payloads are fully encrypted.
"""

import math
import statistics
from typing import List, Dict, Any, Optional


def analyze_beaconing(
    packet_timestamps: List[float],
    packet_sizes: Optional[List[int]] = None,
    protocols_found: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Analyze packet inter-arrival times and sizes for periodic beaconing patterns.

    Parameters:
      packet_timestamps: List of epoch float timestamps (seconds).
      packet_sizes: Optional list of packet byte sizes.
      protocols_found: List of protocols detected (e.g. ['IKE', 'ESP']).

    Returns:
      Dict with anomaly score (0-100), timing regularity, estimated interval,
      jitter, verdict, and explanatory forensic insights.
    """
    if not packet_timestamps or len(packet_timestamps) < 5:
        return {
            "status": "insufficient_data",
            "anomaly_score": 0.0,
            "anomaly_level": "LOW",
            "beacon_detected": False,
            "timing_regularity_pct": 0.0,
            "size_consistency_pct": 0.0,
            "estimated_interval_sec": None,
            "jitter_sec": None,
            "coefficient_of_variation": None,
            "verdict": "Insufficient Packets for Timing Analysis",
            "explanation": "At least 5 packet timestamps are required to calculate inter-arrival regularity.",
            "insights": [
                "Fewer than 5 packets observed; statistical timing regularity cannot be evaluated."
            ],
        }

    # Sort timestamps to ensure strict monotonic ordering
    ts_sorted = sorted([float(t) for t in packet_timestamps if t is not None])
    if len(ts_sorted) < 5:
        return {
            "status": "insufficient_data",
            "anomaly_score": 0.0,
            "anomaly_level": "LOW",
            "beacon_detected": False,
            "verdict": "Insufficient Valid Timestamps",
            "explanation": "Valid timestamp count is below threshold.",
            "insights": [],
        }

    # Compute positive Inter-Arrival Times (IAT)
    iats: List[float] = []
    for i in range(1, len(ts_sorted)):
        diff = ts_sorted[i] - ts_sorted[i - 1]
        if diff > 1e-6:  # ignore simultaneous sub-microsecond arrivals
            iats.append(diff)

    if len(iats) < 4:
        return {
            "status": "insufficient_data",
            "anomaly_score": 0.0,
            "anomaly_level": "LOW",
            "beacon_detected": False,
            "verdict": "Insufficient Non-Zero Intervals",
            "explanation": "Packet arrivals are simultaneous or lack distinct interval variance.",
            "insights": ["Nearly all packets arrived simultaneously; inter-arrival timing is negligible."],
        }

    # ── 1. Basic IAT Statistics ───────────────────────────────────────────────
    mean_iat = statistics.mean(iats)
    std_iat = statistics.stdev(iats) if len(iats) > 1 else 0.0
    median_iat = statistics.median(iats)
    min_iat = min(iats)
    max_iat = max(iats)

    # Coefficient of Variation (CV = std / mean)
    # Low CV (< 0.35) implies strictly periodic heartbeats (low jitter).
    # High CV (> 1.0) implies sporadic / human-interactive / bursty traffic.
    cv_iat = (std_iat / mean_iat) if mean_iat > 0 else 99.0

    # ── 2. Periodic Clustering around Median ──────────────────────────────────
    # Check percentage of intervals within ±25% of median interval
    if median_iat > 0:
        lower_bound = 0.75 * median_iat
        upper_bound = 1.25 * median_iat
        cluster_count = sum(1 for x in iats if lower_bound <= x <= upper_bound)
        cluster_ratio = cluster_count / len(iats)
    else:
        cluster_ratio = 0.0

    # ── 3. Burstiness Detection ───────────────────────────────────────────────
    # Sub-50ms packets typically indicate streaming / bulk transfer bursts
    burst_count = sum(1 for x in iats if x < 0.05)
    burst_ratio = burst_count / len(iats)

    # ── 4. Packet Size Regularity ─────────────────────────────────────────────
    size_regularity_pct = 0.0
    is_small_payload = False
    if packet_sizes and len(packet_sizes) >= 4:
        valid_sizes = [int(s) for s in packet_sizes if s is not None and s > 0]
        if valid_sizes:
            mean_size = statistics.mean(valid_sizes)
            std_size = statistics.stdev(valid_sizes) if len(valid_sizes) > 1 else 0.0
            size_cv = (std_size / mean_size) if mean_size > 0 else 0.0
            size_regularity_pct = round(max(0.0, min(100.0, (1.0 - min(size_cv, 1.0)) * 100.0)), 1)
            # C2 heartbeats are typically small probe packets (< 350 bytes)
            if mean_size < 350 and size_cv < 0.35:
                is_small_payload = True

    # ── 5. Regularity & Anomaly Score Calculation ─────────────────────────────
    # Timing Regularity (0 to 100%): inversely proportional to CV
    timing_regularity_pct = round(max(0.0, min(100.0, (1.0 - min(cv_iat, 1.5) / 1.5) * 100.0)), 1)

    # Raw score components:
    # A. Timing regularity contribution (up to 45 pts)
    score_timing = (timing_regularity_pct / 100.0) * 45.0

    # B. Periodic clustering ratio contribution (up to 35 pts)
    score_cluster = cluster_ratio * 35.0

    # C. Beaconing interval suitability (up to 20 pts)
    # Real C2 beacons operate at meaningful intervals (e.g. 0.5s to 300s).
    # Rapid packets (< 0.1s) are usually stream bursts, not periodic C2 beacons.
    score_interval = 0.0
    if 0.5 <= median_iat <= 120.0:
        score_interval = 20.0
    elif 0.2 <= median_iat < 0.5:
        score_interval = 12.0
    elif median_iat > 120.0:
        score_interval = 10.0
    else:  # median < 0.2s (fast burst)
        score_interval = max(0.0, 5.0 * (1.0 - burst_ratio))

    raw_score = score_timing + score_cluster + score_interval

    # Bonus: Small, uniform packet payloads characteristic of heartbeat probes (+10)
    if is_small_payload and timing_regularity_pct > 60:
        raw_score += 10.0

    # Penalty: High burst ratio (streaming/file transfer packets)
    if burst_ratio > 0.6:
        raw_score *= (1.0 - (burst_ratio - 0.5))

    anomaly_score = round(max(0.0, min(100.0, raw_score)), 1)

    # ── 6. Verdict & Insights Generation ──────────────────────────────────────
    insights: List[str] = []
    beacon_detected = False

    if anomaly_score >= 68.0:
        anomaly_level = "HIGH"
        beacon_detected = True
        verdict = "High Risk: Periodic Beaconing Detected (Strong C2 Indicator)"
        insights.append(
            f"Observed strict inter-arrival periodicity around {median_iat:.2f}s "
            f"with low jitter (CV = {cv_iat:.2f})."
        )
        insights.append(
            f"{int(cluster_ratio * 100)}% of packet intervals fall tightly within ±25% of the median interval."
        )
        if is_small_payload:
            insights.append("Packet sizes are uniformly small, consistent with automated heartbeat probes.")
    elif anomaly_score >= 40.0:
        anomaly_level = "ELEVATED"
        beacon_detected = False
        verdict = "Moderate: Semi-Periodic Activity / Automated Polling"
        insights.append(
            f"Moderate timing regularity observed (CV = {cv_iat:.2f}, interval ~{median_iat:.2f}s)."
        )
        insights.append(
            "May correspond to automated keep-alives, network NTP/DNS sync, or jittered C2 beacons."
        )
    else:
        anomaly_level = "LOW"
        beacon_detected = False
        verdict = "Normal: Aperiodic / Human Interactive Traffic"
        insights.append(
            f"High inter-arrival time variance (CV = {cv_iat:.2f}) indicates sporadic, non-periodic traffic."
        )
        if burst_ratio > 0.3:
            insights.append(
                f"{int(burst_ratio * 100)}% of packets arrived in fast bursts (<50ms), typical of interactive sessions or streaming."
            )

    return {
        "status": "evaluated",
        "anomaly_score": anomaly_score,
        "anomaly_level": anomaly_level,
        "beacon_detected": beacon_detected,
        "timing_regularity_pct": timing_regularity_pct,
        "size_consistency_pct": size_regularity_pct,
        "estimated_interval_sec": round(median_iat, 3) if median_iat > 0 else None,
        "jitter_sec": round(std_iat, 3) if std_iat > 0 else None,
        "coefficient_of_variation": round(cv_iat, 3),
        "mean_iat_sec": round(mean_iat, 3),
        "median_iat_sec": round(median_iat, 3),
        "total_intervals_analyzed": len(iats),
        "verdict": verdict,
        "explanation": (
            f"Timing regularity index is {timing_regularity_pct}%. "
            f"Median interval is ~{median_iat:.2f}s (Jitter: ±{std_iat:.2f}s). "
            + ("Periodic beaconing signature detected." if beacon_detected else "No persistent periodic beaconing detected.")
        ),
        "insights": insights,
    }
