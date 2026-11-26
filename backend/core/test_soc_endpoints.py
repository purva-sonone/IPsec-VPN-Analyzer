"""
test_soc_endpoints.py – Tests for get_user_soc_feed() and GET /api/findings.

Covers:
- Empty user data
- Findings aggregation (without leaking full_result)
- Anomaly classification (beaconing + security rules, distinguishing ordinary traffic)
- Deterministic Finding IDs across repeated calls & legacy findings without rule_id
- SQLite and MongoDB storage paths
- Strict user-level data isolation
"""

import os
import tempfile
import pytest
from fastapi import HTTPException

from core import auth, database
from api.auth_routes import register, RegisterRequest
from api.routes import list_user_findings


@pytest.fixture(autouse=True)
def isolated_sqlite_db(monkeypatch):
    """Use an isolated temporary SQLite database for every test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    monkeypatch.setattr(auth, "SQLITE_DB_PATH", temp_db_path)
    monkeypatch.setattr(database, "SQLITE_DB_PATH", temp_db_path)
    monkeypatch.setattr(database, "MONGO_URI", None)
    monkeypatch.setattr(database, "db_backend", "sqlite")

    database.init_db()
    auth.init_auth_tables()

    yield temp_db_path

    try:
        os.remove(temp_db_path)
    except Exception:
        pass


def _make_sample_report(
    analysis_id: str,
    filename: str = "vpn_capture.pcap",
    findings: list | None = None,
    beaconing: dict | None = None,
    risk_score: int = 3,
    risk_level: str = "High",
    skipped: list | None = None,
    explainability: dict | None = None,
) -> dict:
    return {
        "id": analysis_id,
        "filename": filename,
        "status": "completed",
        "pcap_metrics": {
            "packet_count": 25,
            "protocols_found": ["IKE", "ESP"],
            "vpn_mode_inferred": "Tunnel (Inferred – ESP detected as outer layer)",
            "ike_version": "IKEv2",
            "encryption": "DES-CBC",
            "authentication": "Not Extracted",
            "key_exchange": "Group 2 (1024-bit MODP)",
            "beaconing_analysis": beaconing,
        },
        "security_assessment": {
            "overall_risk_score": risk_score,
            "risk_level": risk_level,
            "score_explanation": f"Risk score {risk_score} derived from observed parameters.",
            "findings": findings if findings is not None else [
                {
                    "title": "Weak or Deprecated Encryption Algorithm",
                    "description": "DES-CBC is weak.",
                    "severity": "High",
                    "recommendation": "Upgrade to AES-GCM-256.",
                    "evidence": "Observed in IKE SA proposal: DES-CBC",
                    "risk_contribution": 3,
                },
                {
                    "title": "IKEv2 Detected",
                    "description": "IKEv2 is recommended.",
                    "severity": "Informational",
                    "recommendation": "No action required.",
                    "evidence": "Observed exchange type indicates IKEv2.",
                    "risk_contribution": 0,
                },
            ],
            "rules_evaluated": [
                {"rule": "Encryption Algorithm Strength", "observed_value": "DES-CBC", "status": "FAIL"}
            ],
            "rules_skipped": skipped if skipped is not None else [
                {"rule": "Authentication Method", "reason": "IKE_AUTH not present in capture."}
            ],
        },
        "ml_prediction": {
            "predicted_category": "CHAT",
            "confidence_score": 0.62,
            "model_status": "active",
            "model_note": "500-Tree RF",
            "features_required_missing": [],
            "explainability": explainability if explainability is not None else {
                "summary": "Classification driven by Mean Packet Length.",
                "top_contributing_factors": [
                    {"feature_name": "Mean Packet Length", "value": 210.0, "importance": 0.35}
                ],
            },
        },
    }


def test_empty_user_returns_empty_soc_feed():
    reg = register(RegisterRequest(username="soc_empty_user", password="password123"))
    user = auth.validate_token(reg.token)
    res = list_user_findings(user={"username": user["username"], "user_id": user["user_id"]})

    assert res["findings"] == []
    assert res["anomalies"] == []
    assert res["advisor_context"]["analyses_count"] == 0
    assert res["advisor_context"]["skipped_rules"] == []
    assert res["advisor_context"]["ml_explanations"] == []


def test_findings_and_anomaly_aggregation():
    reg = register(RegisterRequest(username="soc_agg_user", password="password123"))
    user = auth.validate_token(reg.token)
    uid = user["user_id"]

    # Analysis 1: High security finding + detected periodic beaconing
    report_1 = _make_sample_report(
        "anl-111111",
        filename="beacon_capture.pcap",
        beaconing={
            "status": "analyzed",
            "anomaly_score": 82.0,
            "anomaly_level": "HIGH",
            "beacon_detected": True,
            "confidence_level": "HIGH",
            "estimated_interval_sec": 5.0,
            "jitter_sec": 0.05,
            "verdict": "Periodic Beaconing Indicator Detected",
            "explanation": "Regular 5.0s intervals observed across encrypted ESP flow.",
            "insights": ["Observed low IAT variance (CV = 0.01)."],
        },
    )
    # Analysis 2: Ordinary informational traffic (no anomalies)
    report_2 = _make_sample_report(
        "anl-222222",
        filename="normal_ikev2.pcap",
        risk_score=0,
        risk_level="Informational",
        findings=[
            {
                "title": "IKEv2 Detected",
                "description": "Standard IKEv2.",
                "severity": "Informational",
                "recommendation": "No action required.",
                "evidence": "Observed IKEv2.",
                "risk_contribution": 0,
            }
        ],
        beaconing={
            "status": "analyzed",
            "anomaly_score": 10.0,
            "anomaly_level": "LOW",
            "beacon_detected": False,
            "confidence_level": "LOW",
            "verdict": "Irregular / Non-Periodic Traffic",
            "explanation": "No periodic pattern detected.",
            "insights": [],
        },
    )

    database.save_analysis(report_1, user_id=uid)
    database.save_analysis(report_2, user_id=uid)

    res = list_user_findings(user={"username": user["username"], "user_id": uid})

    # Findings: 2 from report_1 + 1 from report_2 = 3 total (security rules only)
    assert len(res["findings"]) == 3
    for f in res["findings"]:
        assert "full_result" not in f
        assert f["finding_id"].startswith("FND-")
        assert f["analysis_id"] in ("anl-111111", "anl-222222")

    # Anomalies: ONLY behavioral anomaly from beaconing_detector on report_1
    # Security rule findings must NOT be duplicated in anomalies
    anomalies = res["anomalies"]
    assert len(anomalies) == 1
    assert anomalies[0]["analysis_id"] == "anl-111111"
    assert anomalies[0]["source"] == "beaconing_detector"
    assert anomalies[0]["observation_type"] == "Inferred"
    assert anomalies[0]["anomaly_score"] == 82.0
    assert anomalies[0]["anomaly_level"] == "HIGH"
    assert anomalies[0]["severity"] == "High"


def test_elevated_and_insufficient_beaconing_classification():
    """ELEVATED beaconing (score >= 40) is flagged as Medium anomaly;
    insufficient_data and LOW are not flagged."""
    reg = register(RegisterRequest(username="soc_elev_user", password="password123"))
    user = auth.validate_token(reg.token)
    uid = user["user_id"]

    elevated_rep = _make_sample_report(
        "anl-elev-1",
        findings=[],
        beaconing={
            "status": "evaluated",
            "anomaly_score": 44.0,
            "anomaly_level": "ELEVATED",
            "beacon_detected": False,
            "confidence_level": "MODERATE",
            "estimated_interval_sec": 12.0,
            "verdict": "Moderate: Semi-Periodic Activity / Automated Polling",
            "explanation": "Moderate timing regularity observed.",
            "insights": ["Moderate timing regularity observed."],
        },
    )
    insufficient_rep = _make_sample_report(
        "anl-insuff-1",
        findings=[],
        beaconing={
            "status": "insufficient_data",
            "anomaly_score": 0.0,
            "anomaly_level": "LOW",
            "beacon_detected": False,
            "verdict": "Insufficient Packets for Timing Analysis",
            "explanation": "At least 5 packet timestamps required.",
            "insights": [],
        },
    )

    database.save_analysis(elevated_rep, user_id=uid)
    database.save_analysis(insufficient_rep, user_id=uid)

    res = list_user_findings(user={"username": user["username"], "user_id": uid})
    assert len(res["anomalies"]) == 1
    assert res["anomalies"][0]["analysis_id"] == "anl-elev-1"
    assert res["anomalies"][0]["anomaly_level"] == "ELEVATED"
    assert res["anomalies"][0]["severity"] == "Medium"
    assert res["anomalies"][0]["beacon_detected"] is False


def test_finding_ids_stable_after_reordering_and_duplicates():
    """Reordering findings must preserve exact Finding IDs; duplicates stay unique."""
    reg = register(RegisterRequest(username="soc_reorder_user", password="password123"))
    user = auth.validate_token(reg.token)
    uid = user["user_id"]

    f_enc = {
        "title": "Weak or Deprecated Encryption Algorithm",
        "description": "DES-CBC is weak.",
        "severity": "High",
        "recommendation": "Upgrade to AES-GCM-256.",
        "evidence": "Observed in IKE SA proposal: DES-CBC",
        "risk_contribution": 3,
    }
    f_ike = {
        "title": "IKEv2 Detected",
        "description": "IKEv2 is recommended.",
        "severity": "Informational",
        "recommendation": "No action required.",
        "evidence": "Observed exchange type indicates IKEv2.",
        "risk_contribution": 0,
    }

    database.save_analysis(_make_sample_report("reorder-01", findings=[f_enc, f_ike]), user_id=uid)
    res_orig = list_user_findings(user={"username": user["username"], "user_id": uid})
    map_orig = {f["title"]: f["finding_id"] for f in res_orig["findings"]}

    # Save same analysis with findings in reverse order
    database.save_analysis(_make_sample_report("reorder-01", findings=[f_ike, f_enc]), user_id=uid)
    res_rev = list_user_findings(user={"username": user["username"], "user_id": uid})
    map_rev = {f["title"]: f["finding_id"] for f in res_rev["findings"]}

    assert map_orig == map_rev

    # True duplicate findings within the same analysis must still get unique IDs
    database.save_analysis(_make_sample_report("dup-01", findings=[f_enc, f_enc]), user_id=uid)
    res_dup = list_user_findings(user={"username": user["username"], "user_id": uid})
    dup_ids = [f["finding_id"] for f in res_dup["findings"] if f["analysis_id"] == "dup-01"]
    assert len(dup_ids) == 2
    assert len(set(dup_ids)) == 2


def test_deterministic_finding_ids_across_calls():
    """Repeated calls must return identical Finding IDs, even for legacy findings without rule_id."""
    reg = register(RegisterRequest(username="soc_det_user", password="password123"))
    user = auth.validate_token(reg.token)
    uid = user["user_id"]

    legacy_report = _make_sample_report("legacy-id-001")
    database.save_analysis(legacy_report, user_id=uid)

    res1 = list_user_findings(user={"username": user["username"], "user_id": uid})
    res2 = list_user_findings(user={"username": user["username"], "user_id": uid})

    ids1 = [f["finding_id"] for f in res1["findings"]]
    ids2 = [f["finding_id"] for f in res2["findings"]]
    assert len(ids1) == 2
    assert ids1 == ids2


def test_cross_user_isolation_on_soc_feed():
    """User A and User B must never see each other's findings, anomalies, or advisor context."""
    reg_a = register(RegisterRequest(username="soc_alice", password="password123"))
    reg_b = register(RegisterRequest(username="soc_bob", password="password456"))
    user_a = auth.validate_token(reg_a.token)
    user_b = auth.validate_token(reg_b.token)

    database.save_analysis(_make_sample_report("alice-cap-1", filename="alice_secret.pcap"), user_id=user_a["user_id"])

    res_a = list_user_findings(user={"username": user_a["username"], "user_id": user_a["user_id"]})
    res_b = list_user_findings(user={"username": user_b["username"], "user_id": user_b["user_id"]})

    assert len(res_a["findings"]) == 2
    assert res_a["advisor_context"]["analyses_count"] == 1

    assert res_b["findings"] == []
    assert res_b["anomalies"] == []
    assert res_b["advisor_context"]["analyses_count"] == 0
    assert res_b["advisor_context"]["skipped_rules"] == []
    assert res_b["advisor_context"]["ml_explanations"] == []


def test_mongodb_path_scoping(monkeypatch):
    """Verify MongoDB branch filters strictly by user_id and returns identical feed shape."""
    captured_queries = []

    class _FakeCursor(list):
        def sort(self, *_args, **_kwargs):
            return self

    class _FakeCollection:
        def find(self, query, projection=None):
            captured_queries.append((query, projection))
            if query.get("user_id") == 42:
                return _FakeCursor([
                    {
                        "id": "mongo-anl-1",
                        "filename": "mongo.pcap",
                        "created_at": "2026-11-26T10:00:00",
                        "risk_score": 3,
                        "risk_level": "High",
                        "predicted_category": "CHAT",
                        "confidence_score": 0.7,
                        "full_result": _make_sample_report("mongo-anl-1", filename="mongo.pcap"),
                    }
                ])
            return _FakeCursor([])

    monkeypatch.setattr(database, "db_backend", "mongodb")
    monkeypatch.setattr(database, "collection", _FakeCollection())
    monkeypatch.setattr(database, "is_db_connected", lambda: True)

    res_42 = database.get_user_soc_feed(user_id=42)
    res_99 = database.get_user_soc_feed(user_id=99)

    assert captured_queries[0][0] == {"user_id": 42}
    assert captured_queries[1][0] == {"user_id": 99}
    assert len(res_42["findings"]) == 2
    assert res_42["findings"][0]["finding_id"].startswith("FND-MONGOA-")
    assert res_99["findings"] == []
    assert res_99["advisor_context"]["analyses_count"] == 0
