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
            "confidence_level": "LOW",
            "confidence_score": 0.0,
            "sample_size_intervals": 0,
            "observation_duration_sec": 0.0,
            "is_small_sample": True,
            "timing_regularity_pct": 0.0,
            "size_consistency_pct": 0.0,
            "estimated_interval_sec": None,
            "jitter_sec": None,
            "coefficient_of_variation": None,
            "mean_iat_sec": None,
            "median_iat_sec": None,
            "total_intervals_analyzed": 0,
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
            "confidence_level": "LOW",
            "confidence_score": 0.0,
            "sample_size_intervals": 0,
            "observation_duration_sec": 0.0,
            "is_small_sample": True,
            "timing_regularity_pct": 0.0,
            "size_consistency_pct": 0.0,
            "estimated_interval_sec": None,
            "jitter_sec": None,
            "coefficient_of_variation": None,
            "mean_iat_sec": None,
            "median_iat_sec": None,
            "total_intervals_analyzed": 0,
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
        duration = max(0.0, ts_sorted[-1] - ts_sorted[0])
        return {
            "status": "insufficient_data",
            "anomaly_score": 0.0,
            "anomaly_level": "LOW",
            "beacon_detected": False,
            "confidence_level": "LOW",
            "confidence_score": 0.0,
            "sample_size_intervals": len(iats),
            "observation_duration_sec": round(duration, 3),
            "is_small_sample": True,
            "timing_regularity_pct": 0.0,
            "size_consistency_pct": 0.0,
            "estimated_interval_sec": None,
            "jitter_sec": None,
            "coefficient_of_variation": None,
            "mean_iat_sec": None,
            "median_iat_sec": None,
            "total_intervals_analyzed": len(iats),
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

    # ── 5. Confidence & Sample Size Scaling ──────────────────────────────────
    duration = max(0.0, ts_sorted[-1] - ts_sorted[0])
    num_intervals = len(iats)

    # Interval count scaling: statistical confidence requires sufficient sample size
    if num_intervals < 6:
        interval_factor = 0.35
    elif num_intervals < 10:
        interval_factor = 0.50
    elif num_intervals < 15:
        interval_factor = 0.70
    elif num_intervals < 20:
        interval_factor = 0.85
    else:
        interval_factor = 1.0

    # Cycle count scaling: ratio of total observation duration to estimated interval
    cycles_observed = (duration / median_iat) if median_iat > 0 else 0.0
    if cycles_observed < 5.0:
        cycle_factor = 0.40
    elif cycles_observed < 10.0:
        cycle_factor = 0.70
    elif cycles_observed < 15.0:
        cycle_factor = 0.85
    else:
        cycle_factor = 1.0

    confidence_score = round(interval_factor * cycle_factor, 2)
    if confidence_score >= 0.75 and num_intervals >= 12:
        confidence_level = "HIGH"
    elif confidence_score >= 0.45 and num_intervals >= 8:
        confidence_level = "MODERATE"
    else:
        confidence_level = "LOW"

    is_small_sample = (num_intervals < 10 or confidence_level == "LOW")

    # ── 6. Regularity & Anomaly Score Calculation ─────────────────────────────
    # Timing Regularity (0 to 100%): inversely proportional to CV
    timing_regularity_pct = round(max(0.0, min(100.0, (1.0 - min(cv_iat, 1.5) / 1.5) * 100.0)), 1)

    # Raw score components:
    # A. Timing regularity contribution (up to 45 pts)
    score_timing = (timing_regularity_pct / 100.0) * 45.0

    # B. Periodic clustering ratio contribution (up to 35 pts)
    score_cluster = cluster_ratio * 35.0

    # C. Beaconing interval suitability (up to 20 pts)
    # Real C2 beacons operate at meaningful intervals (e.g. 0.5s to 300s).
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

    # Apply confidence weighting and sample size damping
    if is_small_sample:
        # Prevent small test captures (e.g. 5 packets / 4 intervals) from receiving 100/100
        # and generating false-positive high-risk alarms.
        scaled_score = raw_score * max(0.35, confidence_score)
        anomaly_score = round(max(0.0, min(45.0, scaled_score)), 1)
    else:
        scaled_score = raw_score * max(0.70, confidence_score)
        anomaly_score = round(max(0.0, min(100.0, scaled_score)), 1)

    # ── 7. Verdict & Insights Generation ──────────────────────────────────────
    insights: List[str] = []
    beacon_detected = False

    if anomaly_score >= 68.0 and not is_small_sample:
        anomaly_level = "HIGH"
        beacon_detected = True
        verdict = "High Risk: Periodic Beaconing Detected (Behavioral C2 Indicator)"
        insights.append(
            f"Observed persistent inter-arrival periodicity around {median_iat:.2f}s "
            f"with low jitter (CV = {cv_iat:.2f}) across {num_intervals} intervals ({duration:.1f}s window, {confidence_level} confidence)."
        )
        insights.append(
            f"{int(cluster_ratio * 100)}% of packet intervals fall tightly within ±25% of the median interval."
        )
        if is_small_payload:
            insights.append("Packet sizes are uniformly small, consistent with automated heartbeat probes.")
        insights.append(
            "Periodic timing is a behavioral indicator, not definitive proof of malicious activity. "
            "Legitimate automated network functions (e.g. VPN keepalives, Dead Peer Detection, or NTP synchronization) "
            "also generate regular cadence; correlation with endpoint telemetry and destination IP reputation is required."
        )
    elif anomaly_score >= 40.0:
        anomaly_level = "ELEVATED"
        beacon_detected = False
        if is_small_sample:
            verdict = "Moderate: Semi-Periodic Timing / Low-Confidence Sample"
        else:
            verdict = "Moderate: Semi-Periodic Activity / Automated Polling"
        insights.append(
            f"Moderate timing regularity observed (CV = {cv_iat:.2f}, interval ~{median_iat:.2f}s, {confidence_level} confidence)."
        )
        if is_small_sample:
            insights.append(
                f"Small sample size observed ({num_intervals} intervals over {duration:.1f}s). "
                "Statistical confidence is limited; brief periodic sequences commonly reflect synthetic test scripts, ping sweeps, "
                "or initial handshake keep-alives rather than persistent C2 beaconing."
            )
        else:
            insights.append(
                "May correspond to routine background keep-alives, network NTP/DNS sync, or jittered C2 beacons."
            )
        insights.append(
            "Periodic timing is a behavioral indicator, not definitive proof of compromise."
        )
    else:
        anomaly_level = "LOW"
        beacon_detected = False
        if is_small_sample and timing_regularity_pct >= 70.0:
            verdict = "Notice: Regular Cadence in Small Sample (Low Confidence / Behavioral Indicator)"
            insights.append(
                f"Observed regular spacing (~{median_iat:.2f}s) over a minimal sample size ({num_intervals} intervals over {duration:.1f}s). "
                "Due to low sample count, persistent beaconing cannot be reliably evaluated; behavior is consistent with synthetic test scripts or early keep-alives."
            )
        else:
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
        "confidence_level": confidence_level,
        "confidence_score": confidence_score,
        "sample_size_intervals": num_intervals,
        "observation_duration_sec": round(duration, 3),
        "is_small_sample": is_small_sample,
        "timing_regularity_pct": timing_regularity_pct,
        "size_consistency_pct": size_regularity_pct,
        "estimated_interval_sec": round(median_iat, 3) if median_iat > 0 else None,
        "jitter_sec": round(std_iat, 3) if std_iat > 0 else None,
        "coefficient_of_variation": round(cv_iat, 3),
        "mean_iat_sec": round(mean_iat, 3),
        "median_iat_sec": round(median_iat, 3),
        "total_intervals_analyzed": num_intervals,
        "verdict": verdict,
        "explanation": (
            f"Timing regularity index is {timing_regularity_pct}% across {num_intervals} intervals ({duration:.1f}s duration, {confidence_level} confidence). "
            f"Median interval is ~{median_iat:.2f}s (Jitter: ±{std_iat:.2f}s). "
            + ("Periodic beaconing signature detected (behavioral indicator)." if beacon_detected else "No persistent periodic beaconing detected.")
        ),
        "insights": insights,
    }
