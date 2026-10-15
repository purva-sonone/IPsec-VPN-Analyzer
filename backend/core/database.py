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
    """Aggregate stats for the dashboard summary cards."""
    empty_stats = {
        "total_analyses": 0,
        "ipsec_captures": 0,
        "high_risk": 0,
        "informational": 0,
        "ml_classifications": 0,
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
            return {
                "total_analyses": total,
                "ipsec_captures": ipsec,
                "high_risk": high,
                "informational": info,
                "ml_classifications": ml_done,
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

                return {
                    "total_analyses": total,
                    "ipsec_captures": ipsec,
                    "high_risk": high,
                    "informational": info,
                    "ml_classifications": ml_done,
                }
        except Exception as e:
            logger.error("Error retrieving stats from SQLite: %s", e)
            return empty_stats

    return empty_stats
