"""
database.py – MongoDB persistence for IPsec VPN Analyzer history.

Uses pymongo to connect to MongoDB Atlas.
MONGO_URI must be set as an environment variable (e.g. in the Render dashboard).
Never hardcode credentials in this file.
"""

import pymongo
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)

# Load MongoDB URI exclusively from environment variable.
# Set MONGO_URI in the Render dashboard (Environment → Secret Files or Env Vars).
MONGO_URI = os.environ.get("MONGO_URI")  # No hardcoded fallback — credentials must stay secret.

client = None
db = None
collection = None

def init_db():
    """Connect to MongoDB and setup collection. Called once at startup."""
    global client, db, collection
    if not MONGO_URI:
        logger.warning(
            "MONGO_URI environment variable is not set. "
            "MongoDB will be unavailable. Set it in the Render dashboard."
        )
        client = None
        db = None
        collection = None
        return
    try:
        # Connect with a short timeout so it doesn't hang indefinitely if offline or blocked
        _client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
        # Test connection before assigning globals
        _client.admin.command('ping')
        _db = _client["ipsec_analyzer"]
        _collection = _db["analyses"]
        
        # Ensure indexes
        _collection.create_index("id", unique=True)
        _collection.create_index([("created_at", pymongo.DESCENDING)])
        
        client = _client
        db = _db
        collection = _collection
        logger.info("Successfully connected to MongoDB Atlas!")
    except Exception as e:
        logger.error("Failed to connect to MongoDB: %s", e)
        client = None
        db = None
        collection = None


def save_analysis(report: dict):
    """Persist a completed analysis report to MongoDB."""
    if collection is None:
        logger.warning("Cannot save analysis: MongoDB not connected.")
        return

    try:
        m   = report.get("pcap_metrics", {})
        sa  = report.get("security_assessment", {})
        ml  = report.get("ml_prediction", {})

        protocols = ", ".join(m.get("protocols_found", []))

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
            "full_result": report
        }
        
        # Upsert based on the UUID 'id'
        collection.update_one({"id": report["id"]}, {"$set": doc}, upsert=True)
    except Exception as e:
        logger.error("Failed to save analysis to MongoDB: %s", e)


def get_all_analyses() -> list[dict]:
    """Return all analyses ordered newest-first (without full_result blob)."""
    if collection is None:
        return []
    
    try:
        cursor = collection.find(
            {}, 
            {"_id": 0, "full_result": 0}  # Exclude MongoDB ObjectId and heavy payload
        ).sort("created_at", pymongo.DESCENDING)
        return list(cursor)
    except Exception as e:
        logger.error("Error retrieving analyses from MongoDB: %s", e)
        return []


def get_analysis_by_id(analysis_id: str) -> dict | None:
    """Return the full result JSON for a single analysis."""
    if collection is None:
        return None
        
    try:
        doc = collection.find_one({"id": analysis_id}, {"_id": 0, "full_result": 1})
        if doc and "full_result" in doc:
            return doc["full_result"]
        return None
    except Exception as e:
        logger.error("Error retrieving analysis %s from MongoDB: %s", analysis_id, e)
        return None


def delete_analysis(analysis_id: str) -> bool:
    """Delete an analysis. Returns True if a document was deleted."""
    if collection is None:
        return False
        
    try:
        result = collection.delete_one({"id": analysis_id})
        return result.deleted_count > 0
    except Exception as e:
        logger.error("Error deleting analysis %s from MongoDB: %s", analysis_id, e)
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
    if collection is None:
        return empty_stats
        
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
