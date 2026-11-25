"""
timeline.py – Chronological Network Forensics Timeline builder.

Derives structured, factual timeline events strictly from real parsed packet
data without inventing events, timestamps, or false threat labels.
Distinguishes directly Observed events from Inferred observations.
"""

from typing import Optional


def _sort_key(pkt: dict) -> tuple:
    """Sort chronologically by epoch_ts (when available), then by packet number."""
    epoch_ts = pkt.get("epoch_ts")
    try:
        ts_val = float(epoch_ts) if epoch_ts is not None else float("inf")
    except (TypeError, ValueError):
        ts_val = float("inf")

    try:
        num_val = int(pkt.get("number") or 0)
    except (TypeError, ValueError):
        num_val = 0

    return (ts_val, num_val)


def build_forensics_timeline(
    packets: Optional[list[dict]],
    ike_version: str = "Unknown",
) -> list[dict]:
    """
    Build a chronological list of Network Forensics Timeline events from
    extracted packet records.

    Handles missing or unavailable fields safely and never invents events.
    """
    if not packets:
        return []

    ordered_packets = sorted(packets, key=_sort_key)
    events: list[dict] = []
    seen_first_ike = False

    ike_prefix = f"{ike_version} " if ike_version and ike_version not in ("Unknown", "Not Extracted") else ""

    for pkt in ordered_packets:
        pkt_num = pkt.get("number")
        if pkt_num is None:
            continue

        det = pkt.get("details") if isinstance(pkt.get("details"), dict) else {}
        raw_proto = (pkt.get("protocol") or "UNKNOWN").upper()
        src_ip = pkt.get("src_ip") or "—"
        dst_ip = pkt.get("dst_ip") or "—"
        src_port = pkt.get("src_port") if pkt.get("src_port") is not None else det.get("src_port")
        dst_port = pkt.get("dst_port") if pkt.get("dst_port") is not None else det.get("dst_port")
        length = pkt.get("length") if pkt.get("length") is not None else 0

        rel_time = pkt.get("timestamp") or f"pkt #{pkt_num}"
        utc_time = pkt.get("utc_time")
        display_ts = utc_time or rel_time

        observation_type = "Observed"
        observation_note = None
        proto = raw_proto
        event_type = f"{raw_proto} Event"
        description = pkt.get("info") or f"{raw_proto} packet ({length} bytes)"

        # ── IKE / ISAKMP ──────────────────────────────────────────────────────
        if raw_proto in ("IKE", "ISAKMP"):
            proto = "IKE"
            exch = det.get("ike_exchange")
            msg_id = det.get("ike_msg_id")
            is_resp = det.get("ike_is_response")

            if is_resp is True:
                event_type = "IKE Response"
            elif is_resp is False:
                if not seen_first_ike and exch in ("IKE_SA_INIT", "Identity Protection (Main Mode)", "Aggressive Mode"):
                    event_type = "IKE Initiation"
                else:
                    event_type = "IKE Negotiation"
            else:
                if not seen_first_ike and exch in ("IKE_SA_INIT", "Identity Protection (Main Mode)", "Aggressive Mode"):
                    event_type = "IKE Initiation"
                    observation_type = "Inferred"
                    observation_note = "Initiation role inferred from first IKE exchange packet order (response flag unavailable)."
                else:
                    event_type = "IKE Negotiation"

            seen_first_ike = True
            exch_label = exch or "Negotiation"
            msg_label = msg_id if msg_id is not None else "0"
            description = f"{ike_prefix}{exch_label} message (MsgID: {msg_label})"

        # ── ESP ───────────────────────────────────────────────────────────────
        elif raw_proto == "ESP":
            spi = det.get("esp_spi")
            seq = det.get("esp_seq")
            event_type = "ESP Traffic"
            description = f"ESP encrypted payload (SPI: {spi or '—'}, Seq: {seq or '—'})"

        # ── DNS ───────────────────────────────────────────────────────────────
        elif raw_proto == "DNS" or (
            raw_proto == "UDP" and ("53" in (str(src_port or ""), str(dst_port or "")))
        ):
            proto = "DNS"
            dns_q = det.get("dns_query")
            dns_resp = det.get("dns_is_response")
            if raw_proto != "DNS":
                observation_type = "Inferred"
                observation_note = "DNS protocol inferred from UDP port 53."
            if dns_resp is True:
                event_type = "DNS Response"
                description = f"DNS response{f' for {dns_q}' if dns_q else ''}"
            elif dns_resp is False:
                event_type = "DNS Query"
                description = f"DNS query{f' for {dns_q}' if dns_q else ''}"
            else:
                event_type = "DNS Traffic"
                description = f"DNS traffic{f' ({dns_q})' if dns_q else f' ({src_port} → {dst_port})'}"

        # ── TCP ───────────────────────────────────────────────────────────────
        elif raw_proto == "TCP":
            event_type = "TCP Communication"
            if src_port and dst_port:
                description = f"TCP communication ({src_port} → {dst_port}, {length} B)"
            else:
                description = f"TCP packet ({length} bytes)"

        # ── UDP ───────────────────────────────────────────────────────────────
        elif raw_proto == "UDP":
            event_type = "UDP Communication"
            if src_port and dst_port:
                description = f"UDP communication ({src_port} → {dst_port}, {length} B)"
            else:
                description = f"UDP packet ({length} bytes)"

        # ── Other protocols (ICMP, ARP, etc.) ─────────────────────────────────
        else:
            event_type = f"{proto} Traffic"
            description = pkt.get("info") or f"{proto} packet ({length} bytes)"

        events.append({
            "event_id": f"evt-{pkt_num}",
            "packet_number": pkt_num,
            "timestamp": display_ts,
            "relative_time": rel_time,
            "epoch_ts": pkt.get("epoch_ts"),
            "protocol": proto,
            "event_type": event_type,
            "observation_type": observation_type,
            "observation_note": observation_note,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "description": description,
            "details": det,
        })

    return events
