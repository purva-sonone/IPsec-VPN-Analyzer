"""
database.py – Persistence for IPsec VPN Analyzer history.

Supports:
1. MongoDB Atlas when MONGO_URI is configured (e.g., in Render dashboard).
2. Local SQLite fallback (ipsec_history.db) when MONGO_URI is unset or unreachable.
   This guarantees history works out-of-the-box in local development.
"""

import os
import json
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
                    full_result        TEXT NOT NULL
                )
            """)
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


def save_analysis(report: dict):
    """Persist a completed analysis report to MongoDB or SQLite."""
    if not is_db_connected():
        logger.warning("Cannot save analysis: database not initialized.")
        return

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
                        risk_score, risk_level, predicted_category, confidence_score, full_result
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        full_result=excluded.full_result
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
                ))
                conn.commit()
        except Exception as e:
            logger.error("Failed to save analysis to SQLite: %s", e)


def get_all_analyses() -> list[dict]:
    """Return all analyses ordered newest-first (without full_result blob)."""
    if not is_db_connected():
        return []

    if db_backend == "mongodb" and collection is not None:
        try:
            cursor = collection.find(
                {},
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
                cursor.execute("""
                    SELECT id, filename, created_at, status, packet_count,
                           ike_version, protocols, vpn_mode, encryption, dh_group,
                           authentication, risk_score, risk_level, predicted_category,
                           confidence_score
                    FROM analyses
                    ORDER BY created_at DESC
                """)
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error("Error retrieving analyses from SQLite: %s", e)
            return []

    return []


def get_analysis_by_id(analysis_id: str) -> dict | None:
    """Return the full result JSON for a single analysis."""
    if not is_db_connected():
        return None

    if db_backend == "mongodb" and collection is not None:
        try:
            doc = collection.find_one({"id": analysis_id}, {"_id": 0, "full_result": 1})
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
                cursor.execute("SELECT full_result FROM analyses WHERE id = ?", (analysis_id,))
                row = cursor.fetchone()
                if row and row["full_result"]:
                    return json.loads(row["full_result"])
                return None
        except Exception as e:
            logger.error("Error retrieving analysis %s from SQLite: %s", analysis_id, e)
            return None

    return None


def delete_analysis(analysis_id: str) -> bool:
    """Delete an analysis. Returns True if a document was deleted."""
    if not is_db_connected():
        return False

    if db_backend == "mongodb" and collection is not None:
        try:
            result = collection.delete_one({"id": analysis_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error("Error deleting analysis %s from MongoDB: %s", analysis_id, e)
            return False
    elif db_backend == "sqlite":
        try:
            with _get_sqlite_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error("Error deleting analysis %s from SQLite: %s", analysis_id, e)
            return False

    return False


def get_history_stats() -> dict:
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
            total = collection.count_documents({})
            ipsec = collection.count_documents({
                "$or": [
                    {"protocols": {"$regex": "IKE"}},
                    {"protocols": {"$regex": "ESP"}}
                ]
            })
            high = collection.count_documents({"risk_level": {"$in": ["High", "Critical"]}})
            info = collection.count_documents({"risk_level": "Informational"})
            ml_done = collection.count_documents({
                "predicted_category": {"$nin": ["Not Applicable", "Unknown", "", None]}
            })

            docs = list(collection.find({}, {"full_result": 1, "dh_group": 1, "encryption": 1, "vpn_mode": 1, "risk_score": 1, "created_at": 1, "packet_count": 1, "risk_level": 1}))
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
                cursor.execute("SELECT COUNT(*) FROM analyses")
                total = cursor.fetchone()[0]

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
