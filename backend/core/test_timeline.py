"""
Unit tests for backend/core/timeline.py
Tests verify that build_forensics_timeline() generates correct events
from real packet data without inventing or fabricating any events.
"""

import pytest
from core.timeline import build_forensics_timeline


# ---------------------------------------------------------------------------
# Helpers — minimal packet stubs
# ---------------------------------------------------------------------------

def _make_packet(
    number=1,
    timestamp="+0.000000s",
    epoch_ts=1700000000.0,
    utc_time="2023-11-14 22:13:20 UTC",
    src_ip="192.168.1.1",
    dst_ip="192.168.1.2",
    protocol="UDP",
    src_port=500,
    dst_port=500,
    length=100,
    info="",
    details=None,
):
    return {
        "number": number,
        "timestamp": timestamp,
        "epoch_ts": epoch_ts,
        "utc_time": utc_time,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "info": info,
        "details": details or {},
    }


# ---------------------------------------------------------------------------
# Test: empty input
# ---------------------------------------------------------------------------

def test_empty_packets_returns_empty_list():
    result = build_forensics_timeline([], ike_version="IKEv2")
    assert result == []


def test_none_packets_returns_empty_list():
    result = build_forensics_timeline(None, ike_version="IKEv2")
    assert result == []


# ---------------------------------------------------------------------------
# Test: IKE events
# ---------------------------------------------------------------------------

def test_ike_initiation_first_packet():
    """First IKE packet (not a response) should produce IKE Initiation event."""
    pkt = _make_packet(
        number=1,
        protocol="IKE",
        src_port=500,
        dst_port=500,
        details={
            "ike_exchange": "IKE_SA_INIT",
            "ike_is_response": False,
            "ike_msg_id": "0",
        },
    )
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "IKE Initiation"
    assert ev["protocol"] == "IKE"
    assert ev["packet_number"] == 1
    assert ev["observation_type"] == "Observed"


def test_ike_response_event():
    """IKE packet marked as response should produce IKE Response event."""
    pkt = _make_packet(
        number=2,
        epoch_ts=1700000001.0,
        protocol="IKE",
        details={
            "ike_exchange_type": "IKE_SA_INIT",
            "ike_is_response": True,
            "ike_msg_id": "0",
        },
    )
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    assert events[0]["event_type"] == "IKE Response"


def test_ike_negotiation_subsequent_packets():
    """Non-first IKE packets that are neither the first initiator nor flagged as response
    should be labelled as IKE Negotiation."""
    pkts = [
        _make_packet(number=1, protocol="IKE", epoch_ts=1700000000.0,
                     details={"ike_exchange": "IKE_SA_INIT", "ike_is_response": False}),
        _make_packet(number=2, protocol="IKE", epoch_ts=1700000001.0,
                     details={"ike_exchange": "IKE_AUTH", "ike_is_response": False}),
    ]
    events = build_forensics_timeline(pkts, ike_version="IKEv2")
    assert events[0]["event_type"] == "IKE Initiation"
    assert events[1]["event_type"] == "IKE Negotiation"


# ---------------------------------------------------------------------------
# Test: ESP events
# ---------------------------------------------------------------------------

def test_esp_packet_generates_esp_event():
    pkt = _make_packet(
        number=5,
        protocol="ESP",
        src_port=None,
        dst_port=None,
        details={"esp_spi": "0xABCD1234", "esp_sequence": "1"},
    )
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "ESP Traffic"
    assert ev["protocol"] == "ESP"
    assert ev["details"].get("esp_spi") == "0xABCD1234"


# ---------------------------------------------------------------------------
# Test: DNS inference
# ---------------------------------------------------------------------------

def test_dns_port_inferred_from_udp_port_53():
    """UDP packet on port 53 should be classified as DNS (inferred)."""
    pkt = _make_packet(
        number=3,
        protocol="UDP",
        src_port=12345,
        dst_port=53,
        details={},
    )
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    ev = events[0]
    assert ev["protocol"] == "DNS"
    assert ev["observation_type"] == "Inferred"


def test_dns_protocol_explicit():
    """Packet already labelled DNS should produce a DNS event."""
    pkt = _make_packet(
        number=4,
        protocol="DNS",
        src_port=12345,
        dst_port=53,
        details={"dns_query": "example.com", "dns_is_response": False},
    )
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    ev = events[0]
    assert ev["protocol"] == "DNS"
    assert ev["details"].get("dns_query") == "example.com"


# ---------------------------------------------------------------------------
# Test: TCP / UDP generic
# ---------------------------------------------------------------------------

def test_tcp_packet_generates_tcp_event():
    pkt = _make_packet(number=6, protocol="TCP", src_port=1234, dst_port=443)
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    assert events[0]["protocol"] == "TCP"


def test_udp_packet_non_dns_generates_udp_event():
    pkt = _make_packet(number=7, protocol="UDP", src_port=1024, dst_port=4500)
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1
    assert events[0]["protocol"] == "UDP"


# ---------------------------------------------------------------------------
# Test: chronological ordering
# ---------------------------------------------------------------------------

def test_events_sorted_chronologically():
    pkts = [
        _make_packet(number=3, epoch_ts=1700000003.0, protocol="TCP"),
        _make_packet(number=1, epoch_ts=1700000001.0, protocol="UDP"),
        _make_packet(number=2, epoch_ts=1700000002.0, protocol="ESP",
                     src_port=None, dst_port=None, details={}),
    ]
    events = build_forensics_timeline(pkts, ike_version="IKEv2")
    epoch_ts_list = [ev["epoch_ts"] for ev in events]
    assert epoch_ts_list == sorted(epoch_ts_list), "Events must be in ascending epoch_ts order"


# ---------------------------------------------------------------------------
# Test: missing / None fields handled safely
# ---------------------------------------------------------------------------

def test_missing_ip_fields_dont_crash():
    pkt = _make_packet(number=1, src_ip=None, dst_ip=None, protocol="TCP", src_port=None, dst_port=None)
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    # Should not raise; event still created with None IPs
    assert len(events) == 1
    assert events[0]["src_ip"] == "—" or events[0]["src_ip"] is None


def test_missing_epoch_ts_handled():
    """Packet with no epoch_ts should not crash timeline builder."""
    pkt = {
        "number": 1,
        "timestamp": "+0.000s",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": 80,
        "dst_port": 443,
        "length": 60,
        "info": "",
        "details": {},
        # epoch_ts intentionally omitted
    }
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert len(events) == 1


def test_missing_details_key_handled():
    pkt = _make_packet(number=1, protocol="IKE")
    pkt.pop("details")  # remove details entirely
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    # Should not raise
    assert len(events) == 1


# ---------------------------------------------------------------------------
# Test: event_id uniqueness
# ---------------------------------------------------------------------------

def test_all_events_have_unique_event_ids():
    pkts = [
        _make_packet(number=i, epoch_ts=float(1700000000 + i), protocol="TCP")
        for i in range(1, 11)
    ]
    events = build_forensics_timeline(pkts, ike_version="IKEv2")
    ids = [ev["event_id"] for ev in events]
    assert len(ids) == len(set(ids)), "Each event must have a unique event_id"


# ---------------------------------------------------------------------------
# Test: mixed protocol packet list
# ---------------------------------------------------------------------------

def test_mixed_protocols_all_produce_events():
    pkts = [
        _make_packet(number=1, epoch_ts=1700000001.0, protocol="IKE",
                     details={"ike_exchange_type": "IKE_SA_INIT", "ike_is_response": False}),
        _make_packet(number=2, epoch_ts=1700000002.0, protocol="ESP",
                     src_port=None, dst_port=None, details={"esp_spi": "0x1234ABCD"}),
        _make_packet(number=3, epoch_ts=1700000003.0, protocol="UDP",
                     src_port=1024, dst_port=53, details={}),
        _make_packet(number=4, epoch_ts=1700000004.0, protocol="TCP"),
    ]
    events = build_forensics_timeline(pkts, ike_version="IKEv2")
    protocols = [ev["protocol"] for ev in events]
    assert "IKE" in protocols
    assert "ESP" in protocols
    assert "DNS" in protocols  # inferred from UDP port 53
    assert "TCP" in protocols


# ---------------------------------------------------------------------------
# Test: observation type
# ---------------------------------------------------------------------------

def test_ike_events_are_observed_not_inferred():
    pkt = _make_packet(number=1, protocol="IKE",
                       details={"ike_exchange": "IKE_SA_INIT", "ike_is_response": False})
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert events[0]["observation_type"] == "Observed"


def test_esp_events_indicate_encrypted_payload():
    pkt = _make_packet(number=1, protocol="ESP", src_port=None, dst_port=None,
                       details={"esp_spi": "0xDEADBEEF"})
    events = build_forensics_timeline([pkt], ike_version="IKEv2")
    assert events[0]["observation_type"] == "Observed"
    assert "encrypted" in events[0]["description"].lower()


# ---------------------------------------------------------------------------
# Integration tests with real PCAP samples & user isolation
# ---------------------------------------------------------------------------

def test_real_pcap_generates_chronological_timeline():
    """Analyze a real IKEv1 PCAP and verify timeline events match packet data."""
    import asyncio
    import os
    from core.analyzer import analyze_pcap

    pcap_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)),
        "data",
        "ipsec-ikev1-isakmp-main-mode.pcap",
    )
    if not os.path.exists(pcap_path):
        pytest.skip("Sample PCAP not found")

    result = asyncio.run(analyze_pcap(pcap_path))
    packets = result.get("packets") or []
    timeline = result.get("forensics_timeline") or []

    assert len(packets) > 0
    assert len(timeline) == len(packets)

    # Chronological ordering by epoch_ts
    epochs = [ev["epoch_ts"] for ev in timeline if ev.get("epoch_ts") is not None]
    assert epochs == sorted(epochs)

    # Every timeline event corresponds to a real packet number in the PCAP
    pkt_numbers = {p["number"] for p in packets}
    for ev in timeline:
        assert ev["packet_number"] in pkt_numbers

    # Should recognize IKE events
    assert any(ev["protocol"] == "IKE" for ev in timeline)


def test_different_pcaps_produce_distinct_timelines():
    """Two different PCAPs must produce their own distinct timelines."""
    import asyncio
    import os
    from core.analyzer import analyze_pcap

    base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
    pcap_a = os.path.join(base, "ipsec-ikev1-isakmp-main-mode.pcap")
    pcap_b = os.path.join(base, "ipsec_client.pcap")
    if not (os.path.exists(pcap_a) and os.path.exists(pcap_b)):
        pytest.skip("Sample PCAPs not found")

    tl_a = asyncio.run(analyze_pcap(pcap_a)).get("forensics_timeline") or []
    tl_b = asyncio.run(analyze_pcap(pcap_b)).get("forensics_timeline") or []

    assert len(tl_a) > 0 and len(tl_b) > 0
    assert (len(tl_a), [e["timestamp"] for e in tl_a]) != (
        len(tl_b), [e["timestamp"] for e in tl_b]
    )


def test_timeline_backfill_and_cross_user_isolation(monkeypatch):
    """Legacy analyses without stored forensics_timeline are backfilled on read,
    and cross-user access is denied with 404."""
    import os
    import tempfile
    from fastapi import HTTPException
    from core import auth, database
    from api.auth_routes import register, RegisterRequest
    from api.routes import get_history_entry

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        temp_db_path = f.name

    try:
        monkeypatch.setattr(auth, "SQLITE_DB_PATH", temp_db_path)
        monkeypatch.setattr(database, "SQLITE_DB_PATH", temp_db_path)
        monkeypatch.setattr(database, "MONGO_URI", None)
        monkeypatch.setattr(database, "db_backend", "sqlite")
        database.init_db()
        auth.init_auth_tables()

        reg_a = register(RegisterRequest(username="tl_owner", password="password123"))
        reg_b = register(RegisterRequest(username="tl_other", password="password456"))
        user_a = auth.validate_token(reg_a.token)
        user_b = auth.validate_token(reg_b.token)

        legacy_analysis = {
            "id": "tl-legacy-1",
            "filename": "legacy.pcap",
            "status": "completed",
            "pcap_metrics": {
                "packet_count": 2,
                "ike_version": "IKEv2",
                "protocols_found": ["IKE"],
                "packets": [
                    _make_packet(number=1, protocol="IKE", epoch_ts=1700000000.0,
                                 details={"ike_exchange": "IKE_SA_INIT", "ike_is_response": False}),
                    _make_packet(number=2, protocol="IKE", epoch_ts=1700000001.0,
                                 details={"ike_exchange": "IKE_SA_INIT", "ike_is_response": True}),
                ],
                # forensics_timeline intentionally omitted
            },
            "security_assessment": {
                "overall_risk_score": 2,
                "risk_level": "Low",
                "findings": [],
                "recommendations": [],
            },
        }
        database.save_analysis(legacy_analysis, user_id=user_a["user_id"])

        # Owner gets backfilled timeline
        res = get_history_entry("tl-legacy-1", user={"username": user_a["username"], "user_id": user_a["user_id"]})
        tl = res["pcap_metrics"].get("forensics_timeline")
        assert isinstance(tl, list) and len(tl) == 2
        assert tl[0]["event_type"] == "IKE Initiation"
        assert tl[1]["event_type"] == "IKE Response"

        # Other user is denied access
        with pytest.raises(HTTPException) as exc:
            get_history_entry("tl-legacy-1", user={"username": user_b["username"], "user_id": user_b["user_id"]})
        assert exc.value.status_code == 404
    finally:
        try:
            os.remove(temp_db_path)
        except Exception:
            pass
