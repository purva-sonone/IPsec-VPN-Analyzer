import pyshark
import os
import asyncio
import subprocess
import shutil
import logging
import time
import math
import sys
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Thread pool for running PyShark in isolation from Uvicorn's event loop
_executor = ThreadPoolExecutor(max_workers=4)

# ── TShark auto-discovery ─────────────────────────────────────────────────────

_WINDOWS_PATHS = [
    r'C:\Program Files\Wireshark\tshark.exe',
    r'C:\Program Files (x86)\Wireshark\tshark.exe',
    r'C:\Wireshark\tshark.exe',
]
_UNIX_PATHS = [
    '/usr/bin/tshark',
    '/usr/local/bin/tshark',
    '/opt/homebrew/bin/tshark',
    '/usr/sbin/tshark',
]

# Cached result — resolved once at startup / first call
_tshark_path_cache: str | None = None
_tshark_missing_msg: str | None = None


def _discover_tshark() -> str:
    """
    Discover the TShark executable using this priority order:
      1. TSHARK_PATH environment variable
      2. shutil.which('tshark')  — checks the system PATH
      3. Common Windows installation paths
      4. Common Linux/macOS installation paths

    Returns the resolved path string if found.
    Raises RuntimeError with a clear, actionable setup message if not found.
    """
    global _tshark_path_cache, _tshark_missing_msg

    # Return cached result from a previous call
    if _tshark_path_cache is not None:
        return _tshark_path_cache
    if _tshark_missing_msg is not None:
        raise RuntimeError(_tshark_missing_msg)

    source = None

    # 1. Environment variable override
    env_path = os.environ.get('TSHARK_PATH', '').strip()
    if env_path and os.path.isfile(env_path):
        _tshark_path_cache = env_path
        source = 'TSHARK_PATH env variable'
        logger.info('TShark discovered via %s: %s', source, _tshark_path_cache)
        return _tshark_path_cache

    # 2. System PATH
    which_result = shutil.which('tshark')
    if which_result and os.path.isfile(which_result):
        _tshark_path_cache = which_result
        source = 'system PATH'
        logger.info('TShark discovered via %s: %s', source, _tshark_path_cache)
        return _tshark_path_cache

    # 3. Common Windows paths
    for candidate in _WINDOWS_PATHS:
        if os.path.isfile(candidate):
            _tshark_path_cache = candidate
            source = 'windows_default'
            logger.info('TShark discovered via %s: %s', source, _tshark_path_cache)
            return _tshark_path_cache

    # 4. Common Linux/macOS paths
    for candidate in _UNIX_PATHS:
        if os.path.isfile(candidate):
            _tshark_path_cache = candidate
            source = 'unix_default'
            logger.info('TShark discovered via %s: %s', source, _tshark_path_cache)
            return _tshark_path_cache

    # Not found — build a clear, actionable error
    os_name = 'Windows' if sys.platform.startswith('win') else sys.platform
    expected = _WINDOWS_PATHS if sys.platform.startswith('win') else _UNIX_PATHS
    _tshark_missing_msg = (
        f"TShark is required for PCAP analysis but was not found.\n"
        f"  Detected OS      : {os_name}\n"
        f"  Expected paths   : {', '.join(expected[:2])}\n"
        f"  Fix option 1     : Install Wireshark from https://www.wireshark.org/download.html\n"
        f"  Fix option 2     : Set the TSHARK_PATH environment variable to the full path\n"
        f"                     of tshark.exe (Windows) or tshark (Linux/Mac)"
    )
    logger.error('TShark not found. %s', _tshark_missing_msg)
    raise RuntimeError(_tshark_missing_msg)


def get_tshark_info() -> dict:
    """
    Return TShark discovery information for the /api/system/dependencies endpoint.
    Never raises — always returns a dict.
    """
    try:
        path = _discover_tshark()
    except RuntimeError:
        os_name = 'Windows' if sys.platform.startswith('win') else sys.platform
        expected = _WINDOWS_PATHS if sys.platform.startswith('win') else _UNIX_PATHS
        return {
            'available': False,
            'path': None,
            'version': None,
            'source': None,
            'error': (
                'TShark not found. Install Wireshark from '
                'https://www.wireshark.org/download.html '
                'or set the TSHARK_PATH environment variable.'
            ),
            'os': os_name,
            'expected_paths': expected[:3],
        }

    # Get version
    version_line = None
    try:
        r = subprocess.run(
            [path, '--version'],
            capture_output=True, text=True, timeout=5
        )
        version_line = r.stdout.split('\n')[0].strip() if r.stdout else None
    except Exception:
        pass

    # Determine source
    env_path = os.environ.get('TSHARK_PATH', '').strip()
    if env_path and path == env_path:
        source = 'TSHARK_PATH env variable'
    elif shutil.which('tshark') == path:
        source = 'system PATH'
    elif path in _WINDOWS_PATHS:
        source = 'windows_default'
    else:
        source = 'unix_default'

    return {
        'available': True,
        'path': path,
        'version': version_line,
        'source': source,
    }

# ── Algorithm ID → human-readable name mappings ───────────────────────────────

_ENCR_ALGORITHMS = {
    # IKEv1 Oakley Encryption Algorithm IDs
    '1': 'DES-CBC', '2': 'IDEA-CBC', '3': 'Blowfish-CBC',
    '4': 'RC5-R16-B64-CBC', '5': '3DES-CBC', '6': 'CAST-CBC',
    '7': 'AES-CBC', '8': 'CAMELLIA-CBC',
    # IKEv2 Transform Type 1 (RFC 5996)
    '11': 'NULL Encryption', '12': 'AES-CBC',
    '13': 'AES-CTR',
    '14': 'AES-CCM-8', '15': 'AES-CCM-12', '16': 'AES-CCM-16',
    '18': 'AES-GCM-8', '19': 'AES-GCM-12', '20': 'AES-GCM-16',
    '28': 'ChaCha20-Poly1305',
}

_AUTH_ALGORITHMS = {
    '1': 'HMAC-MD5-96', '2': 'HMAC-SHA1-96', '3': 'DES-MAC',
    '4': 'KPDK-MD5', '5': 'AES-XCBC-96',
    '12': 'HMAC-SHA2-256-128', '13': 'HMAC-SHA2-384-192',
    '14': 'HMAC-SHA2-512-256',
}

_AUTH_METHODS = {
    '1': 'Pre-Shared Key (PSK)', '2': 'DSS Signatures',
    '3': 'RSA Signatures', '4': 'RSA Encryption',
    '9': 'ECDSA-256', '10': 'ECDSA-384', '11': 'ECDSA-521',
    '14': 'Digital Signature (RFC 7427)',
}

_DH_GROUPS = {
    '1':  'Group 1 (768-bit MODP)',
    '2':  'Alternate 1024-bit MODP group',
    '5':  'Group 5 (1536-bit MODP)',
    '14': 'Group 14 (2048-bit MODP)',
    '15': 'Group 15 (3072-bit MODP)',
    '16': 'Group 16 (4096-bit MODP)',
    '19': 'Group 19 (ECP-256)',
    '20': 'Group 20 (ECP-384)',
    '21': 'Group 21 (ECP-521)',
    '31': 'Group 31 (Curve25519)',
}

# IKEv2 exchange types (RFC 7296): SA_INIT=34, AUTH=35, CREATE_CHILD=36, INFO=37
_IKEv2_EXCHANGE_TYPES = {34, 35, 36, 37}
# IKEv1 exchange types: ID_PROT=2, AGGRESSIVE=4, INFO=5, QUICK_MODE=6
_IKEv1_EXCHANGE_TYPES = {2, 4, 5, 6, 32}


def _safe_get(layer, *field_names: str, reject_zero: bool = True):
    """
    Try multiple field names on a PyShark layer.
    Returns the first non-empty, non-trivial string value found.

    When reject_zero is False, '0' is accepted as a valid value.
    This is needed for numeric IDs where 0 could theoretically be valid,
    but more importantly, we must not reject values like '2', '3', '5'
    which are legitimate crypto algorithm IDs.
    """
    trivial = {'none', '', '00:00:00:00'}
    if reject_zero:
        trivial.add('0')
    for name in field_names:
        try:
            val = getattr(layer, name, None)
            if val is None:
                continue
            s = str(val).strip()
            if s and s.lower() not in trivial:
                return s
        except Exception:
            continue
    return None


def _detect_ike_version(isakmp_layer):
    """
    Detect IKE version from the ISAKMP version byte or exchange type.
    Returns 'IKEv1', 'IKEv2', or None if undetermined.
    """
    # Method 1: version byte — high nibble = major (IKEv1=0x10, IKEv2=0x20)
    ver_raw = _safe_get(isakmp_layer, 'version')
    if ver_raw:
        try:
            v = int(ver_raw, 16) if ver_raw.lower().startswith('0x') else int(ver_raw)
            major = (v >> 4) & 0x0F
            if major in (1, 2):
                return f'IKEv{major}'
        except (ValueError, TypeError):
            pass

    # Method 2: exchange type (often more reliably exposed by TShark)
    et_raw = _safe_get(isakmp_layer, 'exchangetype')
    if et_raw:
        try:
            et = int(et_raw)
            if et in _IKEv2_EXCHANGE_TYPES:
                return 'IKEv2'
            if et in _IKEv1_EXCHANGE_TYPES:
                return 'IKEv1'
        except (ValueError, TypeError):
            pass

    return None


def _parse_transform_attrs(isakmp_layer, results: dict):
    """
    Try to extract encryption algorithm, DH group, and authentication from
    ISAKMP transform attribute fields. Updates results dict in-place.

    Field names discovered via PyShark diagnostics:
      IKEv1:  ike_attr_encryption_algorithm, ike_attr_authentication_method,
              ike_attr_group_description
      IKEv2:  tf_id_encr, key_exchange_dh_group, tf_id_prf
    """
    # ── Encryption algorithm ──────────────────────────────────────────────
    if results["encryption"] == "Not Extracted":
        enc_raw = _safe_get(
            isakmp_layer,
            # IKEv1 — actual PyShark attribute (from isakmp.ike.attr.encryption_algorithm)
            'ike_attr_encryption_algorithm',
            # IKEv2 — transform ID for encryption (from isakmp.tf_id_encr)
            'tf_id_encr',
            # Additional fallbacks for other TShark versions
            'encr_alg',
            'enc_alg',
            reject_zero=False,
        )
        if enc_raw:
            resolved = _ENCR_ALGORITHMS.get(enc_raw)
            results["encryption"] = resolved if resolved else enc_raw
            logger.info("Extracted encryption: raw=%s resolved=%s", enc_raw, results["encryption"])

    # ── DH Group ──────────────────────────────────────────────────────────
    if results["key_exchange"] == "Not Extracted":
        dh_raw = _safe_get(
            isakmp_layer,
            # IKEv1 — actual PyShark attribute (from isakmp.ike.attr.group_description)
            'ike_attr_group_description',
            # IKEv2 — Key Exchange DH Group (from isakmp.key_exchange.dh_group)
            'key_exchange_dh_group',
            # IKEv2 — transform ID for DH (from isakmp.tf_id_dh)
            'tf_id_dh',
            # Additional fallbacks
            'dh_group',
            reject_zero=False,
        )
        if dh_raw:
            resolved = _DH_GROUPS.get(dh_raw)
            results["key_exchange"] = resolved if resolved else f'DH Group {dh_raw}'
            logger.info("Extracted DH group: raw=%s resolved=%s", dh_raw, results["key_exchange"])

    # ── Authentication (method or integrity algorithm) ────────────────────
    if results["authentication"] == "Not Extracted":
        auth_raw = _safe_get(
            isakmp_layer,
            # IKEv1 — actual PyShark attribute (from isakmp.ike.attr.authentication_method)
            'ike_attr_authentication_method',
            # IKEv2 — not typically in SA_INIT; may appear in AUTH exchange
            'auth_method',
            # Additional fallbacks
            'integ_alg',
            reject_zero=False,
        )
        if auth_raw:
            resolved = _AUTH_METHODS.get(auth_raw) or _AUTH_ALGORITHMS.get(auth_raw)
            results["authentication"] = resolved if resolved else auth_raw
            logger.info("Extracted authentication: raw=%s resolved=%s", auth_raw, results["authentication"])


def _tshark_fallback(file_path: str, tshark_path: str) -> dict:
    """
    Fallback: run TShark subprocess with -T fields to extract IKE transform
    attributes directly. Used when PyShark's layer attribute access fails to
    expose the fields.

    Returns a dict with keys: encryption, key_exchange, authentication.
    Values are "Not Extracted" when the field was not found.
    """
    fields = {
        "encryption": "Not Extracted",
        "authentication": "Not Extracted",
        "key_exchange": "Not Extracted",
    }
    try:
        cmd = [
            tshark_path,
            '-r', file_path,
            '-T', 'fields',
            '-e', 'isakmp.ike.attr.encryption_algorithm',
            '-e', 'isakmp.ike.attr.authentication_method',
            '-e', 'isakmp.ike.attr.group_description',
            '-e', 'isakmp.key_exchange.dh_group',
            '-e', 'isakmp.tf_id_encr',
            '-e', 'isakmp.tf_id_dh',
            '-Y', 'isakmp',
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            logger.debug("TShark fallback returned code %d (likely unsupported fields for this capture)", result.returncode)
            return fields

        for line in result.stdout.strip().splitlines():
            parts = line.split('\t')
            if len(parts) < 6:
                continue
            ikev1_enc, ikev1_auth, ikev1_dh, ikev2_dh, ikev2_enc, ikev2_dh_tf = parts

            # Encryption: prefer IKEv1 field, then IKEv2
            if fields["encryption"] == "Not Extracted":
                enc_raw = ikev1_enc.strip() or ikev2_enc.strip()
                if enc_raw:
                    resolved = _ENCR_ALGORITHMS.get(enc_raw)
                    fields["encryption"] = resolved if resolved else enc_raw

            # DH group: prefer IKEv1 group_description, then IKEv2 key_exchange_dh_group, then tf_id_dh
            if fields["key_exchange"] == "Not Extracted":
                dh_raw = ikev1_dh.strip() or ikev2_dh.strip() or ikev2_dh_tf.strip()
                if dh_raw:
                    resolved = _DH_GROUPS.get(dh_raw)
                    fields["key_exchange"] = resolved if resolved else f'DH Group {dh_raw}'

            # Authentication: IKEv1 field
            if fields["authentication"] == "Not Extracted":
                auth_raw = ikev1_auth.strip()
                if auth_raw:
                    resolved = _AUTH_METHODS.get(auth_raw) or _AUTH_ALGORITHMS.get(auth_raw)
                    fields["authentication"] = resolved if resolved else auth_raw

            # Stop if all found
            if all(v != "Not Extracted" for v in fields.values()):
                break

        logger.info("TShark fallback results: %s", fields)
    except FileNotFoundError:
        logger.warning("TShark binary not found at %s for fallback", tshark_path)
    except subprocess.TimeoutExpired:
        logger.warning("TShark fallback timed out")
    except Exception as e:
        logger.warning("TShark fallback error: %s", e)

    return fields


def _run_pyshark_sync(file_path: str) -> dict:
    """
    Runs PyShark synchronously inside its OWN isolated asyncio event loop.
    This function is always called in a background thread so it never
    conflicts with Uvicorn's running event loop.
    """
    results = {
        "protocols_found": [],
        "packet_count": 0,
        "vpn_mode_inferred": "Unknown",
        "ike_version": "Unknown",
        "encryption": "Not Extracted",
        "authentication": "Not Extracted",
        "key_exchange": "Not Extracted",
        # Flow-level features for ML classification
        # These are populated during packet iteration and finalised after the loop
        "flow_features": None,
    }

    # Accumulators for flow-level feature extraction
    _pkt_timestamps: list = []    # epoch float seconds per packet
    _pkt_sizes: list = []         # bytes per packet
    _out_iats: list = []          # outgoing inter-arrival times
    _in_iats: list = []           # incoming inter-arrival times
    _prev_out_ts: float = None
    _prev_in_ts:  float = None
    _total_out_bytes: int = 0
    _total_in_bytes:  int = 0
    _total_out_pkts:  int = 0
    _total_in_pkts:   int = 0

    tshark_path = _discover_tshark()  # auto-discover: env var → PATH → common locations

    try:
        # Create a fresh event loop for PyShark in this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cap = pyshark.FileCapture(
            file_path,
            keep_packets=False,
            tshark_path=tshark_path,
            eventloop=loop,
        )
        for pkt in cap:
            results["packet_count"] += 1

            # ── Per-packet flow feature collection ──────────────────────────
            try:
                pkt_len = int(pkt.length)
                pkt_ts  = float(pkt.sniff_timestamp)
            except Exception:
                pkt_len = 0
                pkt_ts  = None

            if pkt_ts is not None:
                _pkt_timestamps.append(pkt_ts)
                _pkt_sizes.append(pkt_len)

                # Determine packet direction via IP src/dst heuristic:
                # The first src IP seen is treated as the local initiator ("out").
                # Reverse direction is "in". Falls back gracefully if IP layer missing.
                try:
                    pkt_src = pkt.ip.src
                    if not hasattr(_run_pyshark_sync, '_local_ip'):
                        _run_pyshark_sync._local_ip = pkt_src
                    is_outgoing = (pkt_src == _run_pyshark_sync._local_ip)
                except Exception:
                    is_outgoing = True  # default: treat as outgoing

                if is_outgoing:
                    _total_out_bytes += pkt_len
                    _total_out_pkts  += 1
                    if _prev_out_ts is not None:
                        _out_iats.append(pkt_ts - _prev_out_ts)
                    _prev_out_ts = pkt_ts
                else:
                    _total_in_bytes += pkt_len
                    _total_in_pkts  += 1
                    if _prev_in_ts is not None:
                        _in_iats.append(pkt_ts - _prev_in_ts)
                    _prev_in_ts = pkt_ts

            # ── ESP detection ───────────────────────────────────────────────
            if 'ESP' in pkt:
                if "ESP" not in results["protocols_found"]:
                    results["protocols_found"].append("ESP")

            # ── ISAKMP / IKE detection ──────────────────────────────────────
            if 'ISAKMP' in pkt:
                if "IKE" not in results["protocols_found"]:
                    results["protocols_found"].append("IKE")

                isakmp = pkt['ISAKMP']

                # Detect IKE version on each ISAKMP packet until known
                if results["ike_version"] == "Unknown":
                    detected = _detect_ike_version(isakmp)
                    if detected:
                        results["ike_version"] = detected

                # Parse transform attributes (keep trying until all fields found)
                _parse_transform_attrs(isakmp, results)

        cap.close()
        loop.close()

        # ── Compute flow-level features after packet loop ────────────────────
        # Reset direction heuristic state for next call
        if hasattr(_run_pyshark_sync, '_local_ip'):
            del _run_pyshark_sync._local_ip

        def _safe_stats(values):
            """Return (min, max, mean, std) or (0,0,0,0) if list is empty."""
            if not values:
                return 0.0, 0.0, 0.0, 0.0
            mn  = min(values)
            mx  = max(values)
            avg = sum(values) / len(values)
            variance = sum((x - avg) ** 2 for x in values) / len(values)
            return mn, mx, avg, math.sqrt(variance)

        out_mn, out_mx, out_mean, out_std = _safe_stats(_out_iats)
        in_mn,  in_mx,  in_mean,  in_std  = _safe_stats(_in_iats)
        all_iats = _out_iats + _in_iats
        fl_mn, fl_mx, fl_mean, fl_std = _safe_stats(all_iats)

        if len(_pkt_timestamps) >= 2:
            flow_duration = _pkt_timestamps[-1] - _pkt_timestamps[0]
        else:
            flow_duration = 0.0

        total_bytes = _total_out_bytes + _total_in_bytes
        log_bytes_per_sec = (
            math.log(total_bytes / flow_duration)
            if flow_duration > 0 and total_bytes > 0 else 0.0
        )

        def _safe_log(n):
            return math.log(n) if n > 0 else 0.0

        results["flow_features"] = {
            "out_iat_min":   out_mn,   "out_iat_max":   out_mx,
            "out_iat_mean":  out_mean, "out_iat_std_dev": out_std,
            "in_iat_min":    in_mn,    "in_iat_max":    in_mx,
            "in_iat_mean":   in_mean,  "in_iat_std_dev":  in_std,
            "flow_iat_min":  fl_mn,    "flow_iat_max":   fl_mx,
            "flow_iat_mean": fl_mean,  "flow_iat_std_dev": fl_std,
            "log_bytes_per_sec":             log_bytes_per_sec,
            "log_total_outgoing_packets":     _safe_log(_total_out_pkts),
            "log_total_incoming_packets":     _safe_log(_total_in_pkts),
            "log_total_outgoing_bytes":       _safe_log(_total_out_bytes),
            "log_total_incoming_bytes":       _safe_log(_total_in_bytes),
            # Metadata (not used as model features)
            "flow_duration_seconds": round(flow_duration, 4),
            "total_packets": results["packet_count"],
            "total_bytes": total_bytes,
        }

        # ── TShark subprocess fallback ────────────────────────────────────
        # If PyShark did not extract any crypto parameters, try TShark -T fields
        # directly. This covers edge cases where PyShark attribute access fails.
        still_missing = any(
            results[k] == "Not Extracted"
            for k in ("encryption", "authentication", "key_exchange")
        )
        if still_missing and "IKE" in results["protocols_found"]:
            logger.info("PyShark did not extract all crypto params; trying TShark fallback")
            fallback = _tshark_fallback(file_path, tshark_path)
            for key in ("encryption", "authentication", "key_exchange"):
                if results[key] == "Not Extracted" and fallback[key] != "Not Extracted":
                    results[key] = fallback[key]
                    logger.info("Fallback filled %s = %s", key, results[key])

        # VPN Mode Inference
        # ESP present as a standalone outer-layer protocol is characteristic
        # of Tunnel Mode. Transport Mode shows ESP nested inside original IP.
        if "ESP" in results["protocols_found"]:
            results["vpn_mode_inferred"] = "Tunnel (Inferred — ESP detected as outer layer)"

    except pyshark.tshark.tshark.TSharkNotFoundException:
        raise FileNotFoundError(
            "TShark is not installed or not in the PATH. Please install Wireshark/TShark."
        )
    except Exception as e:
        if "tshark" in str(e).lower() or "not found" in str(e).lower():
            raise FileNotFoundError(
                "TShark is not installed or not in the PATH. Please install Wireshark/TShark."
            )
        raise RuntimeError(f"Packet parsing failed: {e}")

    return results


async def analyze_pcap(file_path: str) -> dict:
    """
    Async entry point for PCAP analysis.
    Offloads the blocking PyShark work to a thread so Uvicorn's
    event loop is never blocked or conflicted.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(_executor, _run_pyshark_sync, file_path)
    return results
