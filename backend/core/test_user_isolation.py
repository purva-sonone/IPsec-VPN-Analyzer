"""
test_user_isolation.py – Tests for user data isolation, ownership enforcement,
and cross-account access denial.
"""

import os
import tempfile
import pytest
from fastapi import HTTPException

from core import auth, database
from api.auth_routes import register, RegisterRequest
from api.routes import (
    list_history,
    history_stats,
    get_history_entry,
    delete_history_entry,
    download_report,
)


@pytest.fixture(autouse=True)
def setup_isolated_db(monkeypatch):
    """Use an isolated temp database for tests so real ipsec_history.db is never touched."""
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


def _make_dummy_analysis(analysis_id: str, filename: str = "capture.pcap", risk_score: int = 2) -> dict:
    return {
        "id": analysis_id,
        "filename": filename,
        "status": "completed",
        "pcap_metrics": {
            "packet_count": 100,
            "ike_version": "IKEv2",
            "protocols_found": ["IKE", "ESP"],
            "vpn_mode_inferred": "Tunnel",
            "encryption": "AES-256-GCM",
            "key_exchange": "DH Group 19",
            "authentication": "PSK",
        },
        "security_assessment": {
            "overall_risk_score": risk_score,
            "risk_level": "Informational",
            "findings": [
                {"title": "Strong Encryption Observed", "severity": "Informational"}
            ],
        },
        "ml_prediction": {
            "predicted_category": "VOIP",
            "confidence_score": 0.95,
        },
    }


def test_new_user_sees_empty_dashboard():
    """A freshly registered user should see zero analyses and empty stats."""
    reg = register(RegisterRequest(username="newuser_test", password="password123"))
    user = auth.validate_token(reg.token)
    user_dict = {"username": user["username"], "user_id": user["user_id"]}

    hist = list_history(user=user_dict)
    assert hist == []

    stats = history_stats(user=user_dict)
    assert stats["total_analyses"] == 0
    assert stats["ipsec_captures"] == 0
    assert stats["high_risk"] == 0


def test_analysis_saved_with_user_id():
    """save_analysis should associate record with user_id correctly."""
    reg = register(RegisterRequest(username="savetest_user", password="password123"))
    user = auth.validate_token(reg.token)
    uid = user["user_id"]

    rep = _make_dummy_analysis("save-test-1", "myfile.pcap")
    database.save_analysis(rep, user_id=uid)

    # Only the owner can retrieve it
    result = database.get_analysis_by_id("save-test-1", user_id=uid)
    assert result is not None
    assert result["id"] == "save-test-1"

    # Others cannot see it
    other_result = database.get_analysis_by_id("save-test-1", user_id=uid + 999)
    assert other_result is None


def test_history_isolation_between_two_accounts():
    """Account B should NOT see Account A's analyses and vice versa."""
    # Register two accounts
    reg_a = register(RegisterRequest(username="alice_iso_test", password="password123"))
    reg_b = register(RegisterRequest(username="bob_iso_test", password="password456"))

    user_a = auth.validate_token(reg_a.token)
    user_b = auth.validate_token(reg_b.token)
    user_a_dict = {"username": user_a["username"], "user_id": user_a["user_id"]}
    user_b_dict = {"username": user_b["username"], "user_id": user_b["user_id"]}

    # Save two analyses for A and one for B
    database.save_analysis(_make_dummy_analysis("iso-a1", "alice1.pcap"), user_id=user_a["user_id"])
    database.save_analysis(_make_dummy_analysis("iso-a2", "alice2.pcap"), user_id=user_a["user_id"])
    database.save_analysis(_make_dummy_analysis("iso-b1", "bob1.pcap"), user_id=user_b["user_id"])

    # A sees 2, B sees 1
    assert len(list_history(user=user_a_dict)) == 2
    assert len(list_history(user=user_b_dict)) == 1

    # Stats are isolated
    assert history_stats(user=user_a_dict)["total_analyses"] == 2
    assert history_stats(user=user_b_dict)["total_analyses"] == 1

    # A's IDs should not contain B's
    a_ids = [r["id"] for r in list_history(user=user_a_dict)]
    assert "iso-a1" in a_ids and "iso-a2" in a_ids
    assert "iso-b1" not in a_ids


def test_cross_account_read_denied():
    """Account B must receive 404 when trying to read Account A's analysis by ID."""
    reg_a = register(RegisterRequest(username="alice_read_test", password="password123"))
    reg_b = register(RegisterRequest(username="bob_read_test", password="password456"))

    user_a = auth.validate_token(reg_a.token)
    user_b = auth.validate_token(reg_b.token)
    user_a_dict = {"username": user_a["username"], "user_id": user_a["user_id"]}
    user_b_dict = {"username": user_b["username"], "user_id": user_b["user_id"]}

    database.save_analysis(_make_dummy_analysis("cross-read-a1"), user_id=user_a["user_id"])

    # Account A can read own analysis
    result = get_history_entry("cross-read-a1", user=user_a_dict)
    assert result["id"] == "cross-read-a1"

    # Account B gets 404
    with pytest.raises(HTTPException) as exc:
        get_history_entry("cross-read-a1", user=user_b_dict)
    assert exc.value.status_code == 404


def test_cross_account_delete_denied():
    """Account B must receive 404 when trying to delete Account A's analysis."""
    reg_a = register(RegisterRequest(username="alice_del_test", password="password123"))
    reg_b = register(RegisterRequest(username="bob_del_test", password="password456"))

    user_a = auth.validate_token(reg_a.token)
    user_b = auth.validate_token(reg_b.token)
    user_a_dict = {"username": user_a["username"], "user_id": user_a["user_id"]}
    user_b_dict = {"username": user_b["username"], "user_id": user_b["user_id"]}

    database.save_analysis(_make_dummy_analysis("cross-del-a1"), user_id=user_a["user_id"])

    # Account B cannot delete Account A's record
    with pytest.raises(HTTPException) as exc:
        delete_history_entry("cross-del-a1", user=user_b_dict)
    assert exc.value.status_code == 404

    # Confirm it was NOT deleted - Account A can still read it
    result = get_history_entry("cross-del-a1", user=user_a_dict)
    assert result["id"] == "cross-del-a1"


def test_cross_account_pdf_report_denied():
    """Account B must receive 404 when trying to download Account A's PDF report."""
    reg_a = register(RegisterRequest(username="alice_pdf_test", password="password123"))
    reg_b = register(RegisterRequest(username="bob_pdf_test", password="password456"))

    user_a = auth.validate_token(reg_a.token)
    user_b = auth.validate_token(reg_b.token)
    user_b_dict = {"username": user_b["username"], "user_id": user_b["user_id"]}

    database.save_analysis(_make_dummy_analysis("cross-pdf-a1"), user_id=user_a["user_id"])

    # Account B cannot download Account A's report
    with pytest.raises(HTTPException) as exc:
        download_report("cross-pdf-a1", user=user_b_dict)
    assert exc.value.status_code == 404


def test_own_delete_works():
    """A user can delete their own analysis."""
    reg = register(RegisterRequest(username="selfdelete_test", password="password123"))
    user = auth.validate_token(reg.token)
    user_dict = {"username": user["username"], "user_id": user["user_id"]}

    database.save_analysis(_make_dummy_analysis("del-own-1"), user_id=user["user_id"])
    database.save_analysis(_make_dummy_analysis("del-own-2"), user_id=user["user_id"])

    # Verify 2 analyses
    assert len(list_history(user=user_dict)) == 2

    # Delete one
    del_res = delete_history_entry("del-own-1", user=user_dict)
    assert "Deleted" in del_res["message"]

    # Verify only 1 remains
    remaining = list_history(user=user_dict)
    assert len(remaining) == 1
    assert remaining[0]["id"] == "del-own-2"
