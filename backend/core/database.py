"""
database.py – Persistence for IPsec VPN Analyzer history.

Supports:
1. MongoDB Atlas when MONGO_URI is configured (e.g., in Render dashboard).
2. Local SQLite fallback (ipsec_history.db) when MONGO_URI is unset or unreachable.
   This guarantees history works out-of-the-box in local development.
"""

import os
import re
import json
import hashlib
import sqlite3
import logging
from datetime import datetime
import pymongo

logger = logging.getLogger(__name__)

# Load MongoDB URI from environment variable.
MONGO_URI = os.environ.get("MONGO_URI")

# Local SQLite database path inside the backend directory.
_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SQLITE_DB_PATH = os.path.join(_BACKEND_DIR, "ipsec_history.db")

# Global connection handles
client = None
db = None
collection = None
db_backend = None  # "mongodb" | "sqlite" | None


def _get_sqlite_conn() -> sqlite3.Connection:
    """Return a configured SQLite connection with row factory."""
    conn = sqlite3.connect(SQLITE_DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def _init_sqlite():
    """Ensure the SQLite analyses table exists."""
    global db_backend
    try:
        with _get_sqlite_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analyses (
                    id                 TEXT PRIMARY KEY,
                    filename           TEXT NOT NULL,
                    created_at         TEXT NOT NULL,
                    status             TEXT NOT NULL,
                    packet_count       INTEGER,
                    ike_version        TEXT,
                    protocols          TEXT,
                    vpn_mode           TEXT,
                    encryption         TEXT,
                    dh_group           TEXT,
                    authentication     TEXT,
                    risk_score         INTEGER,
                    risk_level         TEXT,
                    predicted_category TEXT,
                    confidence_score   REAL,
                    full_result        TEXT NOT NULL,
                    user_id            INTEGER
                )
            """)
            try:
                conn.execute("ALTER TABLE analyses ADD COLUMN user_id INTEGER;")
            except Exception:
                pass
            conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user_created ON analyses(user_id, created_at DESC);")
            conn.commit()
        db_backend = "sqlite"
        logger.info("Using local SQLite database: %s", SQLITE_DB_PATH)
    except Exception as e:
        logger.error("Failed to initialize SQLite database: %s", e)
        db_backend = None


def init_db():
    """Connect to MongoDB Atlas or fall back to local SQLite."""
    global client, db, collection, db_backend

    if MONGO_URI:
        try:
            logger.info("Connecting to MongoDB Atlas...")
            _client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
            _client.admin.command('ping')
            _db = _client["ipsec_analyzer"]
            _collection = _db["analyses"]

            _collection.create_index("id", unique=True)
            _collection.create_index([("created_at", pymongo.DESCENDING)])

            client = _client
            db = _db
            collection = _collection
            db_backend = "mongodb"
            logger.info("Successfully connected to MongoDB Atlas!")
            return
        except Exception as e:
            logger.warning("Failed to connect to MongoDB Atlas: %s. Falling back to local SQLite.", e)
            client = None
            db = None
            collection = None

    # Fallback to local SQLite
    _init_sqlite()


def is_db_connected() -> bool:
    """Return True if either MongoDB or SQLite is ready."""
    return db_backend in ("mongodb", "sqlite")


def get_db_type() -> str:
    """Return 'mongodb', 'sqlite', or 'none'."""
    return db_backend or "none"


def save_analysis(report: dict, user_id: int | None = None):
    """Persist a completed analysis report to MongoDB or SQLite."""
    if not is_db_connected():
        logger.warning("Cannot save analysis: database not initialized.")
        return

    uid = user_id if user_id is not None else report.get("user_id")
    if uid is not None:
        report["user_id"] = uid

    m   = report.get("pcap_metrics", {})
    sa  = report.get("security_assessment", {})
    ml  = report.get("ml_prediction", {})
    protocols = ", ".join(m.get("protocols_found", []))

    if db_backend == "mongodb" and collection is not None:
        try:
            doc = {
                "id": report["id"],
                "filename": report["filename"],
                "created_at": datetime.utcnow().isoformat(),
                "status": report.get("status", "completed"),
                "packet_count": m.get("packet_count"),
                "ike_version": m.get("ike_version"),
                "protocols": protocols,
                "vpn_mode": m.get("vpn_mode_inferred"),
                "encryption": m.get("encryption"),
                "dh_group": m.get("key_exchange"),
                "authentication": m.get("authentication"),
                "risk_score": sa.get("overall_risk_score"),
                "risk_level": sa.get("risk_level"),
                "predicted_category": ml.get("predicted_category"),
                "confidence_score": ml.get("confidence_score"),
                "full_result": report,
                "user_id": uid,
            }
            collection.update_one({"id": report["id"]}, {"$set": doc}, upsert=True)
        except Exception as e:
            logger.error("Failed to save analysis to MongoDB: %s", e)
    elif db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                conn.execute("""
                    INSERT INTO analyses (
                        id, filename, created_at, status, packet_count, ike_version,
                        protocols, vpn_mode, encryption, dh_group, authentication,
                        risk_score, risk_level, predicted_category, confidence_score, full_result,
                        user_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        filename=excluded.filename,
                        created_at=excluded.created_at,
                        status=excluded.status,
                        packet_count=excluded.packet_count,
                        ike_version=excluded.ike_version,
                        protocols=excluded.protocols,
                        vpn_mode=excluded.vpn_mode,
                        encryption=excluded.encryption,
                        dh_group=excluded.dh_group,
                        authentication=excluded.authentication,
                        risk_score=excluded.risk_score,
                        risk_level=excluded.risk_level,
                        predicted_category=excluded.predicted_category,
                        confidence_score=excluded.confidence_score,
                        full_result=excluded.full_result,
                        user_id=excluded.user_id
                """, (
                    report["id"],
                    report["filename"],
                    datetime.utcnow().isoformat(),
                    report.get("status", "completed"),
                    m.get("packet_count"),
                    m.get("ike_version"),
                    protocols,
                    m.get("vpn_mode_inferred"),
                    m.get("encryption"),
                    m.get("key_exchange"),
                    m.get("authentication"),
                    sa.get("overall_risk_score"),
                    sa.get("risk_level"),
                    ml.get("predicted_category"),
                    ml.get("confidence_score"),
                    json.dumps(report),
                    uid,
                ))
                conn.commit()
        except Exception as e:
            logger.error("Failed to save analysis to SQLite: %s", e)


def get_all_analyses(user_id: int | None = None) -> list[dict]:
    """Return all analyses ordered newest-first (without full_result blob)."""
    if not is_db_connected():
        return []

    if db_backend == "mongodb" and collection is not None:
        try:
            query = {"user_id": user_id} if user_id is not None else {}
            cursor = collection.find(
                query,
                {"_id": 0, "full_result": 0}
            ).sort("created_at", pymongo.DESCENDING)
            return list(cursor)
        except Exception as e:
            logger.error("Error retrieving analyses from MongoDB: %s", e)
            return []
    elif db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                cursor = conn.cursor()
                if user_id is not None:
                    cursor.execute("""
                        SELECT id, filename, created_at, status, packet_count,
                               ike_version, protocols, vpn_mode, encryption, dh_group,
                               authentication, risk_score, risk_level, predicted_category,
                               confidence_score, user_id
                        FROM analyses
                        WHERE user_id = ?
                        ORDER BY created_at DESC
                    """, (user_id,))
                else:
                    cursor.execute("""
                        SELECT id, filename, created_at, status, packet_count,
                               ike_version, protocols, vpn_mode, encryption, dh_group,
                               authentication, risk_score, risk_level, predicted_category,
                               confidence_score, user_id
                        FROM analyses
                        ORDER BY created_at DESC
                    """)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error("Error retrieving analyses from SQLite: %s", e)
            return []

    return []


def get_analysis_by_id(analysis_id: str, user_id: int | None = None) -> dict | None:
    """Return the full result JSON for a single analysis."""
    if not is_db_connected():
        return None

    if db_backend == "mongodb" and collection is not None:
        try:
            query = {"id": analysis_id}
            if user_id is not None:
                query["user_id"] = user_id
            doc = collection.find_one(query, {"_id": 0, "full_result": 1})
            if doc and "full_result" in doc:
                return doc["full_result"]
            return None
        except Exception as e:
            logger.error("Error retrieving analysis %s from MongoDB: %s", analysis_id, e)
            return None
    elif db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                cursor = conn.cursor()
                if user_id is not None:
                    cursor.execute("SELECT full_result FROM analyses WHERE id = ? AND user_id = ?", (analysis_id, user_id))
                else:
                    cursor.execute("SELECT full_result FROM analyses WHERE id = ?", (analysis_id,))
                row = cursor.fetchone()
                if row and row["full_result"]:
                    return json.loads(row["full_result"])
                return None
        except Exception as e:
            logger.error("Error retrieving analysis %s from SQLite: %s", analysis_id, e)
            return None

    return None


def delete_analysis(analysis_id: str, user_id: int | None = None) -> bool:
    """Delete an analysis. Returns True if a document was deleted."""
    if not is_db_connected():
        return False

    if db_backend == "mongodb" and collection is not None:
        try:
            query = {"id": analysis_id}
            if user_id is not None:
                query["user_id"] = user_id
            result = collection.delete_one(query)
            return result.deleted_count > 0
        except Exception as e:
            logger.error("Error deleting analysis %s from MongoDB: %s", analysis_id, e)
            return False
    elif db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                cursor = conn.cursor()
                if user_id is not None:
                    cursor.execute("DELETE FROM analyses WHERE id = ? AND user_id = ?", (analysis_id, user_id))
                else:
                    cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error("Error deleting analysis %s from SQLite: %s", analysis_id, e)
            return False

    return False


def get_history_stats(user_id: int | None = None) -> dict:
    """Aggregate stats for the dashboard summary cards, threat matrix, posture score, and timeline."""
    empty_stats = {
        "total_analyses": 0,
        "ipsec_captures": 0,
        "high_risk": 0,
        "informational": 0,
        "ml_classifications": 0,
        "posture_score": 100,
        "threat_matrix": {
            "weak_dh": 0,
            "ikev1_aggressive": 0,
            "beaconing": 0,
            "strong_encryption": 0,
        },
        "activity_timeline": [],
    }
    if not is_db_connected():
        return empty_stats

    if db_backend == "mongodb" and collection is not None:
        try:
            u_filter = {"user_id": user_id} if user_id is not None else {}
            total = collection.count_documents(u_filter)
            if total == 0:
                return empty_stats

            ipsec_q = {**u_filter, "$or": [{"protocols": {"$regex": "IKE"}}, {"protocols": {"$regex": "ESP"}}]}
            ipsec = collection.count_documents(ipsec_q)
            high = collection.count_documents({**u_filter, "risk_level": {"$in": ["High", "Critical"]}})
            info = collection.count_documents({**u_filter, "risk_level": "Informational"})
            ml_done = collection.count_documents({
                **u_filter,
                "predicted_category": {"$nin": ["Not Applicable", "Unknown", "", None]}
            })

            docs = list(collection.find(u_filter, {"full_result": 1, "dh_group": 1, "encryption": 1, "vpn_mode": 1, "risk_score": 1, "created_at": 1, "packet_count": 1, "risk_level": 1}))
            weak_dh = 0
            ikev1_agg = 0
            beaconing = 0
            strong_enc = 0
            posture_scores = []
            timeline_map = {}

            for d in docs:
                res = d.get("full_result", {}) if isinstance(d.get("full_result"), dict) else {}
                sa = res.get("security_assessment", {})
                titles = [f.get("title", "") for f in sa.get("findings", [])]

                if any("Weak Diffie-Hellman" in t for t in titles):
                    weak_dh += 1
                if any("Aggressive Mode" in t for t in titles) or "Aggressive" in (d.get("vpn_mode") or ""):
                    ikev1_agg += 1
                if any(("Periodic Beaconing" in t or "Semi-Periodic" in t or "Periodic C2" in t) for t in titles):
                    beaconing += 1
                if any("Strong Encryption" in t for t in titles) or any(s in (d.get("encryption") or "") for s in ("AES-GCM", "AES-CCM", "ChaCha20")):
                    strong_enc += 1

                rs = d.get("risk_score") if d.get("risk_score") is not None else 0
                posture_scores.append(max(0, min(100, 100 - (rs * 10))))

                c_date = (d.get("created_at") or "")[:10]
                if c_date:
                    if c_date not in timeline_map:
                        timeline_map[c_date] = {"date": c_date, "count": 0, "packets": 0, "high_risk": 0}
                    timeline_map[c_date]["count"] += 1
                    timeline_map[c_date]["packets"] += (d.get("packet_count") or 0)
                    if d.get("risk_level") in ("High", "Critical"):
                        timeline_map[c_date]["high_risk"] += 1

            overall_posture = round(sum(posture_scores) / len(posture_scores)) if posture_scores else 100
            timeline = sorted(timeline_map.values(), key=lambda x: x["date"])

            return {
                "total_analyses": total,
                "ipsec_captures": ipsec,
                "high_risk": high,
                "informational": info,
                "ml_classifications": ml_done,
                "posture_score": overall_posture,
                "threat_matrix": {
                    "weak_dh": weak_dh,
                    "ikev1_aggressive": ikev1_agg,
                    "beaconing": beaconing,
                    "strong_encryption": strong_enc,
                },
                "activity_timeline": timeline,
            }
        except Exception as e:
            logger.error("Error retrieving stats from MongoDB: %s", e)
            return empty_stats
    elif db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                cursor = conn.cursor()
                if user_id is not None:
                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE user_id = ?", (user_id,))
                    total = cursor.fetchone()[0]
                    if total == 0:
                        return empty_stats

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE user_id = ? AND (protocols LIKE '%IKE%' OR protocols LIKE '%ESP%')", (user_id,))
                    ipsec = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE user_id = ? AND risk_level IN ('High', 'Critical')", (user_id,))
                    high = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE user_id = ? AND risk_level = 'Informational'", (user_id,))
                    info = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE user_id = ? AND predicted_category IS NOT NULL AND predicted_category NOT IN ('Not Applicable', 'Unknown', '')", (user_id,))
                    ml_done = cursor.fetchone()[0]

                    cursor.execute("""
                        SELECT id, created_at, packet_count, risk_score, risk_level,
                               dh_group, encryption, vpn_mode, full_result
                        FROM analyses
                        WHERE user_id = ?
                        ORDER BY created_at ASC
                    """, (user_id,))
                else:
                    cursor.execute("SELECT COUNT(*) FROM analyses")
                    total = cursor.fetchone()[0]
                    if total == 0:
                        return empty_stats

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE protocols LIKE '%IKE%' OR protocols LIKE '%ESP%'")
                    ipsec = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE risk_level IN ('High', 'Critical')")
                    high = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE risk_level = 'Informational'")
                    info = cursor.fetchone()[0]

                    cursor.execute("SELECT COUNT(*) FROM analyses WHERE predicted_category IS NOT NULL AND predicted_category NOT IN ('Not Applicable', 'Unknown', '')")
                    ml_done = cursor.fetchone()[0]

                    cursor.execute("""
                        SELECT id, created_at, packet_count, risk_score, risk_level,
                               dh_group, encryption, vpn_mode, full_result
                        FROM analyses
                        ORDER BY created_at ASC
                    """)
                rows = cursor.fetchall()

                weak_dh = 0
                ikev1_agg = 0
                beaconing = 0
                strong_enc = 0
                posture_scores = []
                timeline_map = {}

                for r in rows:
                    blob = json.loads(r["full_result"]) if r["full_result"] else {}
                    sa = blob.get("security_assessment", {})
                    titles = [f.get("title", "") for f in sa.get("findings", [])]

                    # 1. Weak DH: supported by extracted findings
                    if any("Weak Diffie-Hellman" in t for t in titles):
                        weak_dh += 1
                    # 2. IKEv1 Aggressive Mode
                    if any("Aggressive Mode" in t for t in titles) or "Aggressive" in (r["vpn_mode"] or ""):
                        ikev1_agg += 1
                    # 3. Periodic Beaconing Indicators
                    if any(("Periodic Beaconing" in t or "Semi-Periodic" in t or "Periodic C2" in t) for t in titles):
                        beaconing += 1
                    # 4. Strong Encryption Observed
                    if any("Strong Encryption" in t for t in titles) or any(s in (r["encryption"] or "") for s in ("AES-GCM", "AES-CCM", "ChaCha20")):
                        strong_enc += 1

                    rs = r["risk_score"] if r["risk_score"] is not None else 0
                    posture_scores.append(max(0, min(100, 100 - (rs * 10))))

                    c_date = (r["created_at"] or "")[:10]
                    if c_date:
                        if c_date not in timeline_map:
                            timeline_map[c_date] = {"date": c_date, "count": 0, "packets": 0, "high_risk": 0}
                        timeline_map[c_date]["count"] += 1
                        timeline_map[c_date]["packets"] += (r["packet_count"] or 0)
                        if r["risk_level"] in ("High", "Critical"):
                            timeline_map[c_date]["high_risk"] += 1

                overall_posture = round(sum(posture_scores) / len(posture_scores)) if posture_scores else 100
                timeline = sorted(timeline_map.values(), key=lambda x: x["date"])

                return {
                    "total_analyses": total,
                    "ipsec_captures": ipsec,
                    "high_risk": high,
                    "informational": info,
                    "ml_classifications": ml_done,
                    "posture_score": overall_posture,
                    "threat_matrix": {
                        "weak_dh": weak_dh,
                        "ikev1_aggressive": ikev1_agg,
                        "beaconing": beaconing,
                        "strong_encryption": strong_enc,
                    },
                    "activity_timeline": timeline,
                }
        except Exception as e:
            logger.error("Error retrieving stats from SQLite: %s", e)
            return empty_stats

    return empty_stats


def _infer_affected_parameter(title: str, evidence: str = "") -> str:
    """Derive a concise affected parameter label from finding title/evidence."""
    text = f"{title} {evidence}".lower()
    if "ikev1" in text or "ikev2" in text or "ike version" in text or "aggressive" in text:
        return "IKE Version / Mode"
    if "diffie-hellman" in text or "dh group" in text or "modp" in text or "ecp-" in text:
        return "Diffie-Hellman Group"
    if "encryption" in text or "cipher" in text or "aes" in text or "des" in text or "null" in text:
        return "Encryption Algorithm"
    if "authentication" in text or "psk" in text or "pre-shared" in text:
        return "Authentication Method"
    if "esp" in text or "payload" in text:
        return "ESP Payload Protection"
    if "beacon" in text or "c2" in text or "periodic" in text or "interval" in text:
        return "Flow Timing / Beaconing"
    return "IPsec Configuration"


def _make_deterministic_finding_id(
    analysis_id: str,
    rule_or_title: str,
    affected_parameter: str,
    evidence: str = "",
) -> str:
    """
    Generate a deterministic, order-independent Finding ID from stable identity
    fields (analysis_id, rule_id/title, affected_parameter, evidence).
    Never uses random values, timestamps, or list indices.
    """
    clean_aid = re.sub(r"[^A-Za-z0-9]", "", str(analysis_id or "UNK"))[:6].upper() or "UNK"
    raw_key = f"{analysis_id}|{rule_or_title}|{affected_parameter}|{evidence}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:6].upper()
    return f"FND-{clean_aid}-{digest}"


def _build_soc_feed_from_records(records: list[dict]) -> dict:
    """
    Shared extraction helper for SQLite and MongoDB records.
    Extracts only real findings, behavioral anomalies, and advisor context
    without exposing full_result blobs.

    - `findings`: security rule findings only.
    - `anomalies`: behavioral anomalies from beaconing_detector.py only.
    """
    findings: list[dict] = []
    anomalies: list[dict] = []
    risk_summaries: list[dict] = []
    skipped_rules: list[dict] = []
    ml_explanations: list[dict] = []
    beaconing_summaries: list[dict] = []

    for rec in records:
        analysis_id = rec.get("id") or ""
        filename = rec.get("filename") or "Unknown"
        created_at = rec.get("created_at") or ""
        blob = rec.get("full_result")
        if isinstance(blob, str):
            try:
                blob = json.loads(blob)
            except Exception:
                blob = {}
        if not isinstance(blob, dict):
            blob = {}

        sa = blob.get("security_assessment") if isinstance(blob.get("security_assessment"), dict) else {}
        pm = blob.get("pcap_metrics") if isinstance(blob.get("pcap_metrics"), dict) else {}
        ml = blob.get("ml_prediction") if isinstance(blob.get("ml_prediction"), dict) else {}

        # ── 1. Security Rule Findings Only ───────────────────────────────────
        raw_findings = sa.get("findings") if isinstance(sa.get("findings"), list) else []
        seen_id_counts: dict[str, int] = {}
        for f in raw_findings:
            if not isinstance(f, dict):
                continue
            title = f.get("title") or "Security Finding"
            severity = f.get("severity") or "Informational"
            evidence = f.get("evidence") or ""
            risk_contrib = f.get("risk_contribution") or 0
            rule_ref = f.get("rule_id") or title
            affected_param = _infer_affected_parameter(title, evidence)

            base_id = _make_deterministic_finding_id(
                analysis_id=analysis_id,
                rule_or_title=rule_ref,
                affected_parameter=affected_param,
                evidence=evidence,
            )
            seen_id_counts[base_id] = seen_id_counts.get(base_id, 0) + 1
            finding_id = base_id if seen_id_counts[base_id] == 1 else f"{base_id}-{seen_id_counts[base_id]}"

            status = "Action Required" if (severity in ("Critical", "High", "Medium", "Low") or risk_contrib > 0) else "Informational"
            obs_type = "Inferred" if "inferred" in evidence.lower() else "Observed"

            findings.append({
                "finding_id": finding_id,
                "analysis_id": analysis_id,
                "filename": filename,
                "created_at": created_at,
                "title": title,
                "description": f.get("description") or "",
                "severity": severity,
                "status": status,
                "observation_type": obs_type,
                "affected_parameter": affected_param,
                "evidence": evidence,
                "recommendation": f.get("recommendation") or "",
                "risk_contribution": risk_contrib,
            })

        # ── 2. Behavioral Anomalies Only (from beaconing_detector.py) ────────
        beaconing = pm.get("beaconing_analysis") if isinstance(pm.get("beaconing_analysis"), dict) else None
        if beaconing:
            b_status = beaconing.get("status")
            b_score = beaconing.get("anomaly_score")
            b_level = (beaconing.get("anomaly_level") or "LOW").upper()
            b_detected = bool(beaconing.get("beacon_detected"))

            if b_status != "insufficient_data":
                beaconing_summaries.append({
                    "analysis_id": analysis_id,
                    "filename": filename,
                    "created_at": created_at,
                    "verdict": beaconing.get("verdict") or "",
                    "anomaly_score": b_score,
                    "anomaly_level": b_level,
                    "beacon_detected": b_detected,
                    "confidence_level": beaconing.get("confidence_level") or "LOW",
                    "estimated_interval_sec": beaconing.get("estimated_interval_sec"),
                    "jitter_sec": beaconing.get("jitter_sec"),
                    "explanation": beaconing.get("explanation") or "",
                    "insights": beaconing.get("insights") or [],
                })

            # Align strictly with beaconing_detector.py semantics:
            # HIGH (score >= 68, not small sample -> beacon_detected=True) or
            # ELEVATED (score >= 40, semi-periodic / moderate timing anomaly).
            if b_status != "insufficient_data" and (b_detected or b_level in ("HIGH", "ELEVATED")):
                sev = "High" if (b_detected or b_level == "HIGH") else "Medium"
                anm_base = _make_deterministic_finding_id(
                    analysis_id=analysis_id,
                    rule_or_title="beaconing_detector",
                    affected_parameter="Flow Timing / Beaconing",
                    evidence=beaconing.get("verdict") or "",
                )
                anomalies.append({
                    "anomaly_id": f"ANM-{anm_base[4:]}",
                    "analysis_id": analysis_id,
                    "filename": filename,
                    "timestamp": created_at,
                    "source": "beaconing_detector",
                    "title": beaconing.get("verdict") or "Timing Regularity Anomaly",
                    "severity": sev,
                    "anomaly_level": b_level,
                    "beacon_detected": b_detected,
                    "observation_type": "Inferred",
                    "anomaly_score": b_score,
                    "confidence_level": beaconing.get("confidence_level"),
                    "estimated_interval_sec": beaconing.get("estimated_interval_sec"),
                    "description": beaconing.get("explanation") or "",
                    "evidence": (beaconing.get("insights") or [""])[0] if beaconing.get("insights") else "",
                })

        # ── 3. Advisor Context (Risk, Skipped Rules, ML Explainability) ─────
        rules_eval = sa.get("rules_evaluated") if isinstance(sa.get("rules_evaluated"), list) else []
        rules_skip = sa.get("rules_skipped") if isinstance(sa.get("rules_skipped"), list) else []

        risk_summaries.append({
            "analysis_id": analysis_id,
            "filename": filename,
            "created_at": created_at,
            "overall_risk_score": sa.get("overall_risk_score") if sa.get("overall_risk_score") is not None else rec.get("risk_score", 0),
            "risk_level": sa.get("risk_level") or rec.get("risk_level") or "Unknown",
            "score_explanation": sa.get("score_explanation") or "",
            "rules_evaluated_count": len(rules_eval),
            "rules_skipped_count": len(rules_skip),
        })

        for sk in rules_skip:
            if isinstance(sk, dict):
                skipped_rules.append({
                    "analysis_id": analysis_id,
                    "filename": filename,
                    "created_at": created_at,
                    "rule": sk.get("rule") or "Unknown Rule",
                    "reason": sk.get("reason") or "Required packet parameters were not observable.",
                })

        expl = ml.get("explainability") if isinstance(ml.get("explainability"), dict) else None
        ml_explanations.append({
            "analysis_id": analysis_id,
            "filename": filename,
            "created_at": created_at,
            "predicted_category": ml.get("predicted_category") or rec.get("predicted_category") or "Not Applicable",
            "confidence_score": ml.get("confidence_score") if ml.get("confidence_score") is not None else rec.get("confidence_score"),
            "model_status": ml.get("model_status") or "unavailable",
            "model_note": ml.get("model_note") or "",
            "summary": expl.get("summary") if expl else None,
            "top_contributing_factors": expl.get("top_contributing_factors", []) if expl else [],
            "features_required_missing": ml.get("features_required_missing") or [],
        })

    # Sort findings newest-first and anomalies chronologically (oldest -> newest)
    findings.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    anomalies.sort(key=lambda x: x.get("timestamp") or "")

    return {
        "findings": findings,
        "anomalies": anomalies,
        "advisor_context": {
            "analyses_count": len(records),
            "risk_summaries": risk_summaries,
            "skipped_rules": skipped_rules,
            "ml_explanations": ml_explanations,
            "beaconing_summaries": beaconing_summaries,
        },
    }


def get_user_soc_feed(user_id: int | None) -> dict:
    """
    Return aggregated findings, anomaly timeline entries, and advisor context
    strictly scoped to the authenticated user_id.
    """
    empty_feed = {
        "findings": [],
        "anomalies": [],
        "advisor_context": {
            "analyses_count": 0,
            "risk_summaries": [],
            "skipped_rules": [],
            "ml_explanations": [],
            "beaconing_summaries": [],
        },
    }

    if user_id is None or not is_db_connected():
        return empty_feed

    if db_backend == "mongodb" and collection is not None:
        try:
            cursor = collection.find(
                {"user_id": user_id},
                {
                    "_id": 0,
                    "id": 1,
                    "filename": 1,
                    "created_at": 1,
                    "risk_score": 1,
                    "risk_level": 1,
                    "predicted_category": 1,
                    "confidence_score": 1,
                    "full_result": 1,
                },
            ).sort("created_at", pymongo.DESCENDING)
            return _build_soc_feed_from_records(list(cursor))
        except Exception as e:
            logger.error("Error retrieving SOC feed from MongoDB: %s", e)
            return empty_feed

    if db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, filename, created_at, risk_score, risk_level,
                           predicted_category, confidence_score, full_result
                    FROM analyses
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                """, (user_id,))
                rows = [dict(row) for row in cursor.fetchall()]
                return _build_soc_feed_from_records(rows)
        except Exception as e:
            logger.error("Error retrieving SOC feed from SQLite: %s", e)
            return empty_feed

    return empty_feed
