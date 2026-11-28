"""
advisor_routes.py – Authenticated endpoints for the RAG-based IPsec Security Assistant.

All endpoints require `Depends(require_auth)` and strictly scope ChromaDB retrieval
and conversation history to the authenticated user's `user_id`.
"""

from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel

from api.auth_routes import require_auth
from core.rag_chat import (
    GroqChatError,
    OllamaChatError,
    check_advisor_status,
    clear_chat_history,
    generate_rag_answer,
    get_chat_history,
)
from core.rag_store import OllamaEmbeddingError

advisor_router = APIRouter(prefix="/advisor", tags=["advisor"])


class ChatRequest(BaseModel):
    message: str
    analysis_id: Optional[str] = None
    attachment_context: Optional[dict] = None


@advisor_router.get("/status")
def advisor_status(user: dict = Depends(require_auth)):
    """Return active AI backend (Groq or local Ollama) connection status."""
    return check_advisor_status()


@advisor_router.post("/chat")
def advisor_chat(body: ChatRequest, user: dict = Depends(require_auth)):
    """Answer a user question using RAG over their own PCAP analysis reports."""
    user_id = user.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid user session.")

    try:
        return generate_rag_answer(
            user_id=int(user_id),
            message=body.message,
            analysis_id=body.analysis_id,
            attachment_context=body.attachment_context,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (OllamaEmbeddingError, OllamaChatError, GroqChatError) as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Advisor chat failed: {exc}")


@advisor_router.get("/history")
def advisor_history(
    analysis_id: Optional[str] = Query(default=None),
    user: dict = Depends(require_auth),
):
    """Return persisted conversation history for the authenticated user and scope."""
    user_id = user.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid user session.")
    return {
        "analysis_id": analysis_id,
        "messages": get_chat_history(user_id=int(user_id), analysis_id=analysis_id),
    }


@advisor_router.delete("/clear")
def advisor_clear(
    analysis_id: Optional[str] = Query(default=None),
    user: dict = Depends(require_auth),
):
    """Clear conversation history for the authenticated user and scope."""
    user_id = user.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid user session.")
    deleted = clear_chat_history(user_id=int(user_id), analysis_id=analysis_id)
    return {"deleted": deleted, "analysis_id": analysis_id}


@advisor_router.post("/upload")
async def advisor_upload(
    file: UploadFile = File(...),
    user: dict = Depends(require_auth),
):
    """
    Validate and OCR-extract an uploaded image (JPG/JPEG/PNG/WEBP).

    Returns the extracted text and metadata for use as attachment_context in /chat.
    Max 10 MB. No path traversal. User-scoped temp directory.
    """
    from core.document_processor import UploadValidationError, process_uploaded_image

    user_id = user.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid user session.")

    try:
        file_bytes = await file.read()
        result = process_uploaded_image(
            file_bytes=file_bytes,
            original_filename=file.filename,
            user_id=int(user_id),
        )
        return result
    except UploadValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {exc}")


@advisor_router.post("/upload_pdf")
async def advisor_upload_pdf(
    file: UploadFile = File(...),
    user: dict = Depends(require_auth),
):
    """
    Validate and extract text from an uploaded PDF (PyMuPDF text + Tesseract OCR fallback).

    Returns page-numbered extracted text and metadata for use as attachment_context in /chat.
    Max 10 MB, max 50 pages. User-scoped temp directory with guaranteed cleanup.
    """
    from core.document_processor import UploadValidationError, process_uploaded_pdf

    user_id = user.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid user session.")

    try:
        file_bytes = await file.read()
        result = process_uploaded_pdf(
            file_bytes=file_bytes,
            original_filename=file.filename,
            user_id=int(user_id),
            content_type=file.content_type,
        )
        return result
    except UploadValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"PDF upload processing failed: {exc}")
