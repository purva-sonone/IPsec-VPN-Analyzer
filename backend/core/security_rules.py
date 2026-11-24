"""
security_rules.py — Rule-based IPsec security assessment engine.

Evaluates only parameters that were actually extracted from the capture.
Parameters not present in the capture are skipped to avoid false positives.
"""
import re

_NOT_AVAILABLE = {"Not Extracted", "Unknown", "Not Available", "", None}

# Encryption algorithm strength classification
_WEAK_ENCRYPTION = (
    'DES-CBC', 'DES', 'RC5', 'Blowfish', '3DES', 'NULL Encryption',
    'IDEA', 'CAST', 'RC4', 'CAMELLIA-CBC',
)
_STRONG_ENCRYPTION = ('AES-GCM', 'AES-CCM', 'ChaCha20', 'AES-CBC', 'AES-CTR')

# DH Group strength classification
_WEAK_DH   = ('Group 1', 'Group 2', 'Group 5', '768-bit MODP', 'Alternate 1024-bit MODP')
_STRONG_DH = (
    'Group 14', 'Group 15', 'Group 16',
    'Group 19', 'Group 20', 'Group 21',
    'Group 31', 'Group 32',
    '2048-bit MODP', '3072-bit MODP', '4096-bit MODP',
    'ECP-256', 'ECP-384', 'ECP-521', 'Curve25519',
)


def evaluate_security(pcap_results: dict) -> dict:
    """
    Evaluates extracted IPsec parameters against security rules.

    Rules are only applied when the relevant parameter was observed.
    If a parameter was not extractable from the capture, the rule is skipped
    (recorded in 'rules_skipped') to prevent false findings.

    Returns a dict containing:
      - findings          : list of SecurityFinding objects
      - overall_risk_score: integer (0 = no risky parameters observed)
      - risk_level        : "High" | "Medium" | "Low" | "Informational"
      - score_explanation : plain-English summary of what contributed to the score
      - rules_evaluated   : list of rules that ran (with reason)
      - rules_skipped     : list of rules that were skipped (with reason)
    """
    findings      = []
    risk_score    = 0
    rules_evaluated = []
    rules_skipped   = []

    enc      = pcap_results.get("encryption", "")
    dh       = pcap_results.get("key_exchange", "")
    auth     = pcap_results.get("authentication", "")
    ike_ver  = pcap_results.get("ike_version", "")
    protocols = pcap_results.get("protocols_found", [])

    # ── 1. IKE Version ────────────────────────────────────────────────────────
    if ike_ver not in _NOT_AVAILABLE:
        status = "PASS"
        if ike_ver == "IKEv1":
            status = "FAIL"
            findings.append({
                "title": "IKEv1 Detected",
                "description": (
                    "IKEv1 is considered legacy and has known vulnerabilities including "
                    "susceptibility to aggressive-mode dictionary attacks and weaker PFS guarantees."
                ),
                "severity": "Medium",
                "recommendation": "Migrate to IKEv2, which is more modern and secure and supports stronger authentication options such as EAP and certificates.",
                "evidence": f"Observed exchange type indicates {ike_ver}.",
                "risk_contribution": 2,
            })
            risk_score += 2
        elif ike_ver == "IKEv2":
            status = "PASS"
            findings.append({
                "title": "IKEv2 Detected",
                "description": "IKEv2 is the current recommended standard for IKE key exchange.",
                "severity": "Informational",
                "recommendation": "No action required. Ensure IKEv2 features like MOBIKE are enabled if applicable.",
                "evidence": f"Observed exchange type indicates {ike_ver}.",
                "risk_contribution": 0,
            })
            
        rules_evaluated.append({
            "rule": "IKE Version Check",
            "observed_value": ike_ver,
            "status": status,
        })
    else:
        rules_skipped.append({
            "rule": "IKE Version Check",
            "reason": "IKE version was not observable in this capture (no IKE packets or version field not exposed).",
        })

    # ── 2. Encryption Algorithm ───────────────────────────────────────────────
    if enc not in _NOT_AVAILABLE:
        is_weak   = any(w.lower() in enc.lower() for w in _WEAK_ENCRYPTION)
        is_strong = any(s.lower() in enc.lower() for s in _STRONG_ENCRYPTION)
        status = "PASS"
        if is_weak:
            status = "FAIL"
            findings.append({
                "title": "Weak or Deprecated Encryption Algorithm",
                "description": (
                    f"The observed encryption algorithm '{enc}' is considered weak or deprecated "
                    "and does not meet modern cryptographic standards."
                ),
                "severity": "High",
                "recommendation": "Upgrade to AES-GCM-256 or AES-GCM-128 (AEAD ciphers preferred).",
                "evidence": f"Observed in IKE SA proposal: {enc}",
                "risk_contribution": 3,
            })
            risk_score += 3
        elif is_strong:
            status = "PASS"
            findings.append({
                "title": "Strong Encryption Algorithm",
                "description": f"The observed encryption algorithm '{enc}' meets modern cryptographic standards.",
                "severity": "Informational",
                "recommendation": "No action required. Prefer AES-GCM variants for authenticated encryption.",
                "evidence": f"Observed in IKE SA proposal: {enc}",
                "risk_contribution": 0,
            })
        else:
            status = "FAIL"
            findings.append({
                "title": "Unclassified Encryption Algorithm",
                "description": f"The algorithm '{enc}' was observed but is not in the known weak/strong lists.",
                "severity": "Low",
                "recommendation": "Verify this algorithm meets your security policy requirements.",
                "evidence": f"Observed in IKE SA proposal: {enc}",
                "risk_contribution": 1,
            })
            risk_score += 1
            
        rules_evaluated.append({
            "rule": "Encryption Algorithm Strength",
            "observed_value": enc,
            "status": status,
        })
    else:
        rules_skipped.append({
            "rule": "Encryption Algorithm Strength",
            "reason": (
                "Encryption algorithm not extractable. "
                "IKE SA proposals are only visible if the IKE_SA_INIT exchange "
                "is captured and TShark exposes the transform attribute fields."
            ),
        })

    # ── 3. Key Exchange (DH Group) ────────────────────────────────────────────
    if dh not in _NOT_AVAILABLE:
        is_weak_dh   = any(re.search(r'\b' + re.escape(w.lower()) + r'\b', dh.lower()) for w in _WEAK_DH)
        is_strong_dh = any(re.search(r'\b' + re.escape(s.lower()) + r'\b', dh.lower()) for s in _STRONG_DH)
        status = "PASS"
        if is_weak_dh:
            status = "FAIL"
            findings.append({
                "title": "Weak Diffie-Hellman Group",
                "description": (
                    f"The DH group '{dh}' provides an insufficient security margin against modern "
                    "attacks (e.g., Logjam). Groups 1, 2, and 5 are deprecated."
                ),
                "severity": "High",
                "recommendation": "Use DH Group 14 (2048-bit MODP) as minimum, or ECP groups 19/20/21.",
                "evidence": f"Observed in IKE Key Exchange payload: {dh}",
                "risk_contribution": 3,
            })
            risk_score += 3
        elif is_strong_dh:
            status = "PASS"
            findings.append({
                "title": "Adequate Diffie-Hellman Group",
                "description": f"The DH group '{dh}' provides an adequate security margin.",
                "severity": "Informational",
                "recommendation": "Consider ECP groups (19, 20, 21) for elliptic-curve based key exchange.",
                "evidence": f"Observed in IKE Key Exchange payload: {dh}",
                "risk_contribution": 0,
            })
        else:
            status = "FAIL"
            findings.append({
                "title": "Unclassified Diffie-Hellman Group",
                "description": f"The DH group '{dh}' was observed but is not in the known weak/strong lists.",
                "severity": "Low",
                "recommendation": "Verify this DH group meets your security policy requirements.",
                "evidence": f"Observed in IKE Key Exchange payload: {dh}",
                "risk_contribution": 1,
            })
            risk_score += 1
            
        rules_evaluated.append({
            "rule": "Diffie-Hellman Group Strength",
            "observed_value": dh,
            "status": status,
        })
    else:
        rules_skipped.append({
            "rule": "Diffie-Hellman Group Strength",
            "reason": (
                "DH group not extractable. "
                "Key Exchange payload group ID is only present if the IKE_SA_INIT "
                "or IKE_AUTH exchange is captured and the field is exposed by TShark."
            ),
        })

    # ── 4. Authentication ─────────────────────────────────────────────────────
    if auth not in _NOT_AVAILABLE:
        status = "PASS"
        if 'PSK' in auth or 'Pre-Shared Key' in auth:
            status = "FAIL"
            findings.append({
                "title": "Pre-Shared Key Authentication",
                "description": (
                    "PSK-based authentication relies on the secrecy of a shared secret. "
                    "Weak PSKs are vulnerable to offline dictionary attacks."
                ),
                "severity": "Low",
                "recommendation": (
                    "Ensure PSK length is at least 20 characters with high entropy. "
                    "Consider certificate-based authentication for production environments."
                ),
                "evidence": f"Observed authentication method: {auth}",
                "risk_contribution": 1,
            })
            risk_score += 1
        else:
            status = "PASS"
            findings.append({
                "title": "Certificate-Based Authentication",
                "description": f"The observed authentication method '{auth}' uses asymmetric cryptography.",
                "severity": "Informational",
                "recommendation": "Ensure certificate chain validity and key lengths meet your policy.",
                "evidence": f"Observed authentication method: {auth}",
                "risk_contribution": 0,
            })
            
        rules_evaluated.append({
            "rule": "Authentication Method",
            "observed_value": auth,
            "status": status,
        })
    else:
        rules_skipped.append({
            "rule": "Authentication Method",
            "reason": (
                "Authentication method not extractable. "
                "The IKE_AUTH payload is only present if the authentication exchange "
                "is captured and the auth method field is exposed by TShark."
            ),
        })

    # ── 5. ESP Payload Protection ─────────────────────────────────────────────
    if "ESP" in protocols:
        findings.append({
            "title": "ESP Payload Encryption Active",
            "description": (
                "Encapsulating Security Payload (ESP) is actively encrypting network traffic. "
                "Packet payloads are shielded against passive wiretapping and plaintext inspection."
            ),
            "severity": "Informational",
            "recommendation": "Maintain active rekeying policies (e.g. byte or time-based limits) and verify anti-replay windowing.",
            "evidence": f"Observed ESP packets in capture; outer mode: {pcap_results.get('vpn_mode_inferred', 'Tunnel')}.",
            "risk_contribution": 0,
        })
        rules_evaluated.append({
            "rule": "ESP Payload Protection",
            "observed_value": "ESP Encapsulation Present",
            "status": "PASS",
        })
    elif "IKE" in protocols:
        findings.append({
            "title": "Control Channel Only (No Encrypted Data Flow)",
            "description": (
                "The capture contains IKE negotiation exchanges but no ESP encrypted data traffic. "
                "Security of the underlying application data flow could not be verified from this sample."
            ),
            "severity": "Informational",
            "recommendation": "Capture traffic during active tunnel usage to evaluate data-phase payload protection.",
            "evidence": f"Protocols observed: {', '.join(protocols)}. Zero ESP data packets detected.",
            "risk_contribution": 0,
        })
        rules_evaluated.append({
            "rule": "ESP Payload Protection",
            "observed_value": "No ESP Packets Observed",
            "status": "NOT OBSERVED",
        })
    else:
        rules_skipped.append({
            "rule": "ESP Payload Protection",
            "reason": "Neither IKE nor ESP protocols were identified in the analyzed packets.",
        })

    # ── 6. C2 Beaconing & Timing Anomaly ──────────────────────────────────────
    beaconing = pcap_results.get("beaconing_analysis")
    if beaconing and beaconing.get("status") == "evaluated":
        anomaly_score = beaconing.get("anomaly_score", 0.0)
        is_beacon = beaconing.get("beacon_detected", False)
        interval = beaconing.get("estimated_interval_sec") or 0.0
        jitter = beaconing.get("jitter_sec") or 0.0
        regularity = beaconing.get("timing_regularity_pct", 0.0)

        conf_level = beaconing.get("confidence_level", "HIGH" if (is_beacon or anomaly_score >= 68.0) else "MODERATE")
        intervals_cnt = beaconing.get("sample_size_intervals") or beaconing.get("total_intervals_analyzed") or 0
        dur_sec = beaconing.get("observation_duration_sec") or 0.0
        is_small = beaconing.get("is_small_sample", False)

        # High risk finding requires confirmed persistent periodic beaconing without small-sample distortion
        if (is_beacon or anomaly_score >= 68.0) and not is_small:
            sample_info = f" across {intervals_cnt} intervals ({dur_sec:.1f}s window)" if intervals_cnt else ""
            findings.append({
                "title": "Periodic Beaconing Activity Detected",
                "description": (
                    f"Traffic exhibits sustained periodic timing regularity ({regularity}%) with estimated "
                    f"beacon interval of ~{interval:.2f}s (Jitter: ±{jitter:.2f}s){sample_info}. "
                    "Note: Transmission periodicity is a behavioral indicator, not definitive proof of malicious activity; "
                    "benign automated functions (e.g. IPsec Dead Peer Detection, NAT keep-alives, or NTP synchronization) also generate regular cadences. "
                    "Further correlation with destination IP reputation, endpoint telemetry, and tunnel context is required."
                ),
                "severity": "High",
                "recommendation": (
                    "Investigate endpoints generating regular heartbeat traffic. "
                    "Correlate destination IPs with threat intelligence feeds and confirm whether cadence matches authorized VPN keepalive intervals."
                ),
                "evidence": (
                    f"Beaconing Anomaly Score: {anomaly_score}/100 ({conf_level} confidence). "
                    f"Observed Interval: ~{interval:.2f}s (±{jitter:.2f}s)"
                    + (f" across {intervals_cnt} intervals ({dur_sec:.1f}s window)." if intervals_cnt else ".")
                ),
                "risk_contribution": 3,
            })
            risk_score += 3
            rules_evaluated.append({
                "rule": "C2 Beaconing Analysis",
                "observed_value": f"Periodic Beaconing ({anomaly_score}/100, {conf_level} Conf)",
                "status": "FAIL",
            })
        elif anomaly_score >= 40.0 or (is_small and (is_beacon or regularity >= 70.0)):
            sample_note = f" (Sample size limitation: {intervals_cnt} intervals over {dur_sec:.1f}s)" if is_small else ""
            findings.append({
                "title": "Semi-Periodic Automated Traffic Observed",
                "description": (
                    f"Observed timing regularity ({regularity}%, interval ~{interval:.2f}s){sample_note}. "
                    "Periodic timing is a behavioral indicator that commonly corresponds to routine background keepalives (such as DPD or NAT keepalive), "
                    "automated synthetic tests, network synchronization, or early jittered telemetry. "
                    "Current sample size and variance do not support a conclusion of malicious C2 implant activity."
                ),
                "severity": "Informational",
                "recommendation": "Review endpoint scheduled tasks and VPN keepalive configuration to confirm authorized periodicity.",
                "evidence": (
                    f"Timing Anomaly Score: {anomaly_score}/100 ({conf_level} confidence"
                    + (f", {intervals_cnt} intervals analyzed over {dur_sec:.1f}s)." if intervals_cnt else ").")
                ),
                "risk_contribution": 0,
            })
            rules_evaluated.append({
                "rule": "C2 Beaconing Analysis",
                "observed_value": f"Semi-Periodic ({anomaly_score}/100, {conf_level} Conf)",
                "status": "REVIEW" if is_small else "PASS",
            })
        else:
            rules_evaluated.append({
                "rule": "C2 Beaconing Analysis",
                "observed_value": f"Aperiodic / Normal ({anomaly_score}/100)",
                "status": "PASS",
            })
    elif beaconing and beaconing.get("status") == "insufficient_data":
        rules_skipped.append({
            "rule": "C2 Beaconing Analysis",
            "reason": beaconing.get("explanation", "Insufficient packet timestamps to evaluate timing regularity."),
        })

    # ── 7. Determine overall risk level ──────────────────────────────────────
    if risk_score >= 5:
        risk_level = "High"
    elif risk_score >= 3:
        risk_level = "Medium"
    elif risk_score >= 1:
        risk_level = "Low"
    else:
        risk_level = "Informational"

    # ── 6. Build score explanation ────────────────────────────────────────────
    contributing = [f for f in findings if f.get("risk_contribution", 0) > 0]

    if risk_score == 0 and len(rules_skipped) > 0 and len(rules_evaluated) == 0:
        # No rules ran at all — nothing was observed
        score_explanation = (
            "Score 0: No observable IPsec parameters were extracted from this capture. "
            "All security rules were skipped. This does NOT imply the VPN is secure — "
            "the critical parameters (encryption algorithm, DH group, authentication method) "
            "were not visible in the captured packets."
        )
    elif risk_score == 0:
        skipped_count = len(rules_skipped)
        skip_note = (
            f" {skipped_count} rule(s) were skipped because those parameters "
            "were not extractable from this capture."
            if skipped_count > 0 else ""
        )
        score_explanation = (
            f"Score 0: No risk-contributing parameters were found among the "
            f"{len(rules_evaluated)} rule(s) that ran.{skip_note} "
            "A score of 0 does NOT guarantee the VPN is fully secure — "
            "it means no high-risk values were observed in the available data."
        )
    else:
        contributors = "; ".join(
            f"{f['title']} (contributed +{f['risk_contribution']})"
            for f in contributing
        )
        score_explanation = (
            f"Score {risk_score} — Risk contributions: {contributors}."
        )

    return {
        "findings":          findings,
        "overall_risk_score": risk_score,
        "risk_level":        risk_level,
        "score_explanation": score_explanation,
        "rules_evaluated":   rules_evaluated,
        "rules_skipped":     rules_skipped,
    }
