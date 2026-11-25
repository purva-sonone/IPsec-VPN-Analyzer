from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from fastapi.responses import Response
import os
import shutil
import uuid
import logging

logger = logging.getLogger(__name__)
from core.analyzer import analyze_pcap, get_tshark_info
from core.security_rules import evaluate_security
from core.ml_model import predict_traffic_category
from core.database import save_analysis, get_all_analyses, get_analysis_by_id, delete_analysis, get_history_stats, collection as db_collection
from core.timeline import build_forensics_timeline
from core.report_generator import generate_pdf
from models.schemas import AnalysisReport
from api.auth_routes import require_auth

router = APIRouter()

UPLOAD_DIR = "data"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health")
def health_check():
    return {"status": "ok", "message": "Backend is running"}


# ── System / Dependency Status ────────────────────────────────────────────────

@router.get("/system/dependencies")
def system_dependencies():
    """
    Report real-time dependency status.
    Returns availability of TShark, MongoDB, and the ML model.
    Never exposes secrets (DB credentials, internal paths hidden when missing).
    """
    # — TShark —
    tshark_info = get_tshark_info()  # never raises — always returns dict

    # — Database (MongoDB Atlas / Local SQLite) —
    from core.database import is_db_connected, get_db_type
    db_ok = is_db_connected()
    db_backend = get_db_type()
    mongodb_info = {
        "available": db_ok,
        "type": db_backend,
        "label": "Ready — MongoDB" if db_backend == "mongodb" else "Ready — Local DB" if db_backend == "sqlite" else "Unavailable",
    }

    # — ML model —
    import os as _os
    from core.ml_model import _MODEL_PATH, _MODEL_PATH_V2, _MODEL_VERSION, _load_model
    # Check the path that corresponds to the actively-selected model version
    _active_ver = os.environ.get('MODEL_VERSION', _MODEL_VERSION).strip().lower()
    _active_ver = _active_ver if _active_ver in ('v1', 'v2') else 'v2'
    active_model_path = _MODEL_PATH_V2 if _active_ver == 'v2' else _MODEL_PATH
    model_exists = _os.path.isfile(active_model_path)
    ml_classes = None
    if model_exists:
        try:
            clf, le = _load_model(_active_ver)
            if le is not None:
                ml_classes = list(le.classes_)
        except Exception:
            pass
    ml_info = {
        "available": model_exists,
        "version": _active_ver,
        "classes": ml_classes,
    }


    return {
        "tshark":   tshark_info,
        "mongodb":  mongodb_info,
        "ml_model": ml_info,
    }


# ── Upload & Analyze ──────────────────────────────────────────────────────────

@router.post("/upload", response_model=AnalysisReport)
async def upload_pcap(file: UploadFile = File(...), user: dict = Depends(require_auth)):
    if not (file.filename.endswith('.pcap') or
            file.filename.endswith('.pcapng') or
            file.filename.endswith('.cap')):
        raise HTTPException(
            status_code=400,
            detail="Only .pcap, .pcapng, and .cap files are supported"
        )

    # Save the uploaded file with a UUID-based name
    file_id  = str(uuid.uuid4())
    file_ext = os.path.splitext(file.filename)[1]
    safe_fn  = f"{file_id}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, safe_fn)

    try:
        with open(file_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save file: {e}")

    # Run full analysis pipeline
    try:
        pcap_metrics        = await analyze_pcap(file_path)
        security_assessment = evaluate_security(pcap_metrics)
        ml_prediction       = predict_traffic_category(pcap_metrics)

        final_report = {
            "id":                  file_id,
            "filename":            file.filename,
            "status":              "completed",
            "pcap_metrics":        pcap_metrics,
            "security_assessment": security_assessment,
            "ml_prediction":       ml_prediction,
        }

        # Persist analysis to MongoDB or SQLite with user isolation
        user_id = user.get("user_id")
        save_analysis(final_report, user_id=user_id)

    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Packet parsing failed: {e}")
    finally:
        # Cleanup uploaded temporary PCAP file to prevent disk exhaustion
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception as rem_err:
                logger.warning("Failed to remove temporary PCAP file %s: %s", file_path, rem_err)

    return final_report


@router.post("/sample/demo-analyze", response_model=AnalysisReport)
async def analyze_sample_capture(user: dict = Depends(require_auth)):
    """
    Run the full analysis pipeline on the bundled verified sample IPsec PCAP.
    Never fabricates results; runs genuine TShark parsing, security rules, and ML classification.
    """
    sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample_ipsec_traffic.pcap")
    if not os.path.exists(sample_path):
        sample_path = os.path.join(UPLOAD_DIR, "sample_ipsec_traffic.pcap")
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail="Sample PCAP file not found on server.")

    file_id = str(uuid.uuid4())
    temp_path = os.path.join(UPLOAD_DIR, f"{file_id}_sample.pcap")

    try:
        shutil.copyfile(sample_path, temp_path)
        pcap_metrics = await analyze_pcap(temp_path)
        security_assessment = evaluate_security(pcap_metrics)
        ml_prediction = predict_traffic_category(pcap_metrics)

        final_report = {
            "id": file_id,
            "filename": "demo_sample_ipsec.pcap",
            "status": "completed",
            "pcap_metrics": pcap_metrics,
            "security_assessment": security_assessment,
            "ml_prediction": ml_prediction,
        }
        user_id = user.get("user_id")
        save_analysis(final_report, user_id=user_id)
        return final_report
    except Exception as e:
        logger.error("Sample analysis failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Sample PCAP analysis failed: {e}")
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


# ── History ───────────────────────────────────────────────────────────────────

@router.get("/history")
def list_history(user: dict = Depends(require_auth)):
    """Return all previous analyses for the authenticated user (lightweight – no full result blobs)."""
    user_id = user.get("user_id")
    try:
        return get_all_analyses(user_id=user_id)
    except Exception:
        return []


@router.get("/history/stats")
def history_stats(user: dict = Depends(require_auth)):
    """Aggregate dashboard statistics for the authenticated user."""
    user_id = user.get("user_id")
    try:
        return get_history_stats(user_id=user_id)
    except Exception:
        return {
            "total_analyses": 0,
            "ipsec_captures": 0,
            "high_risk": 0,
            "informational": 0,
            "ml_classifications": 0,
        }


@router.get("/history/{analysis_id}")
def get_history_entry(analysis_id: str, user: dict = Depends(require_auth)):
    """Return the full analysis result for a single ID owned by the user."""
    user_id = user.get("user_id")
    result = get_analysis_by_id(analysis_id, user_id=user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    pm = result.get("pcap_metrics")
    if isinstance(pm, dict) and not pm.get("forensics_timeline") and pm.get("packets"):
        pm["forensics_timeline"] = build_forensics_timeline(
            pm.get("packets"),
            pm.get("ike_version", "Unknown"),
        )
    return result


@router.delete("/history/{analysis_id}")
def delete_history_entry(analysis_id: str, user: dict = Depends(require_auth)):
    """Delete a single analysis record owned by the user."""
    user_id = user.get("user_id")
    deleted = delete_analysis(analysis_id, user_id=user_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"message": "Deleted successfully"}


# ── PDF Report ────────────────────────────────────────────────────────────────

@router.get("/history/{analysis_id}/report")
def download_report(analysis_id: str, user: dict = Depends(require_auth)):
    """Generate and stream a PDF report for the given analysis owned by the user."""
    user_id = user.get("user_id")
    result = get_analysis_by_id(analysis_id, user_id=user_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    try:
        pdf_bytes = generate_pdf(result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    safe_name = result.get("filename", analysis_id).replace(" ", "_")
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="ipsec_report_{safe_name}.pdf"'
        },
    )
