"""
database.py – MongoDB persistence for IPsec VPN Analyzer history.

Uses pymongo to connect to MongoDB Atlas.
"""

import pymongo
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

MONGO_URI = "mongodb+srv://purvasonone01:purva123@purva.8bjhhdr.mongodb.net/?appName=purva"

client = None
db = None
collection = None

def init_db():
    """Connect to MongoDB and setup collection. Called once at startup."""
    global client, db, collection
    try:
        # Connect with a timeout so it doesn't hang indefinitely if offline
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = client["ipsec_analyzer"]
        collection = db["analyses"]
        
        # Ensure we can quickly query by our string UUID 'id'
        collection.create_index("id", unique=True)
        # Ensure we can sort by created_at quickly
        collection.create_index([("created_at", pymongo.DESCENDING)])
        
        # Test connection
        client.admin.command('ping')
        logger.info("Successfully connected to MongoDB Atlas!")
    except Exception as e:
        logger.error("Failed to connect to MongoDB: %s", e)


def save_analysis(report: dict):
    """Persist a completed analysis report to MongoDB."""
    if collection is None:
        logger.error("Cannot save analysis: MongoDB not initialized.")
        return

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


def get_all_analyses() -> list[dict]:
    """Return all analyses ordered newest-first (without full_result blob)."""
    if collection is None:
        return []
    
    cursor = collection.find(
        {}, 
        {"_id": 0, "full_result": 0}  # Exclude MongoDB ObjectId and heavy payload
    ).sort("created_at", pymongo.DESCENDING)
    
    return list(cursor)


def get_analysis_by_id(analysis_id: str) -> dict | None:
    """Return the full result JSON for a single analysis."""
    if collection is None:
        return None
        
    doc = collection.find_one({"id": analysis_id}, {"_id": 0, "full_result": 1})
    if doc and "full_result" in doc:
        return doc["full_result"]
    return None


def delete_analysis(analysis_id: str) -> bool:
    """Delete an analysis. Returns True if a document was deleted."""
    if collection is None:
        return False
        
    result = collection.delete_one({"id": analysis_id})
    return result.deleted_count > 0


def get_history_stats() -> dict:
    """Aggregate stats for the dashboard summary cards."""
    if collection is None:
        return {
            "total_analyses": 0,
            "ipsec_captures": 0,
            "high_risk": 0,
            "informational": 0,
            "ml_classifications": 0,
        }
        
    total = collection.count_documents({})
    
    # Count where protocols string contains IKE or ESP
    ipsec = collection.count_documents({
        "$or": [
            {"protocols": {"$regex": "IKE"}},
            {"protocols": {"$regex": "ESP"}}
        ]
    })
    
    high = collection.count_documents({"risk_level": {"$in": ["High", "Critical"]}})
    info = collection.count_documents({"risk_level": "Informational"})
    
    # Count where predicted_category is valid (not empty, Not Applicable, or Unknown)
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
