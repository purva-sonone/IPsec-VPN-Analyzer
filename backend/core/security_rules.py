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
                "recommendation": "Migrate to IKEv2, which provides stronger security guarantees and mandatory EAP support.",
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
                "title": "Certificate/Signature-Based Authentication",
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

    # ── 5. Determine overall risk level ──────────────────────────────────────
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
