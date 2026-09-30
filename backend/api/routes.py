from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import Response
import os
import shutil
import uuid
from core.analyzer import analyze_pcap, get_tshark_info
from core.security_rules import evaluate_security
from core.ml_model import predict_traffic_category
from core.database import save_analysis, get_all_analyses, get_analysis_by_id, delete_analysis, get_history_stats, collection as db_collection
from core.report_generator import generate_pdf
from models.schemas import AnalysisReport

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

    # — MongoDB —
    from core.database import collection as _mongo_collection
    mongo_ok = _mongo_collection is not None
    try:
        if mongo_ok:
            from core.database import client as _mongo_client
            _mongo_client.admin.command('ping')
    except Exception:
        mongo_ok = False
    mongodb_info = {"available": mongo_ok}

    # — ML model —
    import os as _os
    from core.ml_model import _MODEL_PATH, _load_model
    model_exists = _os.path.isfile(_MODEL_PATH)
    ml_classes = None
    if model_exists:
        try:
            clf, le = _load_model()
            if le is not None:
                ml_classes = list(le.classes_)
        except Exception:
            pass
    ml_info = {
        "available": model_exists,
        "classes": ml_classes,
    }

    return {
        "tshark":   tshark_info,
        "mongodb":  mongodb_info,
        "ml_model": ml_info,
    }


# ── Upload & Analyze ──────────────────────────────────────────────────────────

@router.post("/upload", response_model=AnalysisReport)
async def upload_pcap(file: UploadFile = File(...)):
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

        # Persist analysis to MongoDB history
        save_analysis(final_report)

    except FileNotFoundError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Packet parsing failed: {e}")

    return final_report


# ── History ───────────────────────────────────────────────────────────────────

@router.get("/history")
def list_history():
    """Return all previous analyses (lightweight – no full result blobs)."""
    return get_all_analyses()


@router.get("/history/stats")
def history_stats():
    """Aggregate dashboard statistics."""
    return get_history_stats()


@router.get("/history/{analysis_id}")
def get_history_entry(analysis_id: str):
    """Return the full analysis result for a single ID."""
    result = get_analysis_by_id(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return result


@router.delete("/history/{analysis_id}")
def delete_history_entry(analysis_id: str):
    """Delete a single analysis record."""
    deleted = delete_analysis(analysis_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return {"message": "Deleted successfully"}


# ── PDF Report ────────────────────────────────────────────────────────────────

@router.get("/history/{analysis_id}/report")
def download_report(analysis_id: str):
    """Generate and stream a PDF report for the given analysis."""
    result = get_analysis_by_id(analysis_id)
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
