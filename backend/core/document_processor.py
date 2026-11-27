"""
document_processor.py – Secure upload validation and OCR extraction
for the IPsec Security Assistant.

Stage 3: Image Upload and Tesseract OCR (JPG, JPEG, PNG, WEBP).
Security controls:
- Extension allowlist + Pillow content/magic-byte verification
- Strict file size limit (10 MB)
- Safe UUID internal filenames (no user path traversal)
- User-scoped temporary directory with guaranteed cleanup
"""

from __future__ import annotations

import io
import logging
import os
import shutil
import uuid
from typing import Optional

from PIL import Image, UnidentifiedImageError
import pymupdf as fitz  # PyMuPDF
import pytesseract

logger = logging.getLogger(__name__)

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_PIL_FORMATS = {"JPEG", "PNG", "WEBP"}
MAX_IMAGE_BYTES = 10 * 1024 * 1024  # 10 MB

UPLOAD_TEMP_ROOT = os.environ.get(
    "ADVISOR_TEMP_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "advisor_tmp"),
)


class UploadValidationError(ValueError):
    """Raised when an uploaded file fails extension, format, or size validation."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _resolve_tesseract_cmd() -> Optional[str]:
    """Locate tesseract executable on PATH or common Windows install locations."""
    found = shutil.which("tesseract")
    if found:
        return found
    candidates = [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Programs\Tesseract-OCR\tesseract.exe"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _safe_display_name(filename: str | None) -> str:
    base = os.path.basename(filename or "uploaded_image.png").strip()
    return base or "uploaded_image.png"


def process_uploaded_image(
    file_bytes: bytes,
    original_filename: str | None,
    user_id: int,
) -> dict:
    """
    Validate an uploaded image and extract visible text via Tesseract OCR.
    Never invents text when OCR finds nothing or Tesseract is unavailable.
    """
    display_name = _safe_display_name(original_filename)
    ext = os.path.splitext(display_name)[1].lower()

    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        raise UploadValidationError(
            f"Unsupported image format '{ext or 'none'}'. Allowed: JPG, JPEG, PNG, WEBP.",
            status_code=400,
        )

    if not file_bytes:
        raise UploadValidationError("Uploaded image file is empty.", status_code=400)

    if len(file_bytes) > MAX_IMAGE_BYTES:
        raise UploadValidationError(
            f"Image exceeds maximum allowed size of {MAX_IMAGE_BYTES // (1024 * 1024)} MB.",
            status_code=413,
        )

    # Verify actual image content & format (prevents spoofed extensions/executables)
    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            img.verify()
        with Image.open(io.BytesIO(file_bytes)) as img_reopened:
            fmt = (img_reopened.format or "").upper()
            width, height = img_reopened.size
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise UploadValidationError(
            "Uploaded file is not a valid or readable image.",
            status_code=400,
        ) from exc

    if fmt not in ALLOWED_PIL_FORMATS:
        raise UploadValidationError(
            f"Image content format '{fmt or 'unknown'}' is not allowed.",
            status_code=400,
        )

    # Write to a user-scoped safe temp path and clean up unconditionally
    user_tmp_dir = os.path.join(UPLOAD_TEMP_ROOT, f"user_{int(user_id)}")
    os.makedirs(user_tmp_dir, exist_ok=True)
    safe_name = f"{uuid.uuid4().hex}{ext}"
    temp_path = os.path.join(user_tmp_dir, safe_name)

    try:
        with open(temp_path, "wb") as f:
            f.write(file_bytes)

        tess_cmd = _resolve_tesseract_cmd()
        if tess_cmd:
            pytesseract.pytesseract.tesseract_cmd = tess_cmd

        try:
            with Image.open(temp_path) as ocr_img:
                # Convert palette/alpha images cleanly for Tesseract
                if ocr_img.mode not in ("RGB", "L"):
                    ocr_img = ocr_img.convert("RGB")
                raw_text = pytesseract.image_to_string(ocr_img) or ""
        except pytesseract.TesseractNotFoundError:
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "image",
                "mode": "ocr_only",
                "width": width,
                "height": height,
                "extracted_text": "",
                "char_count": 0,
                "status": "ocr_unavailable",
                "message": "Tesseract OCR binary is not installed on the server. Cannot extract text from this image.",
            }
        except Exception as exc:
            logger.warning("OCR extraction failed for user %s: %s", user_id, exc)
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "image",
                "mode": "ocr_only",
                "width": width,
                "height": height,
                "extracted_text": "",
                "char_count": 0,
                "status": "unreadable",
                "message": "Could not extract text from this image. Please try a clearer screenshot.",
            }

        cleaned = raw_text.strip()
        if not cleaned:
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "image",
                "mode": "ocr_only",
                "width": width,
                "height": height,
                "extracted_text": "",
                "char_count": 0,
                "status": "no_text_found",
                "message": "No readable text was detected in this image (OCR-only mode).",
            }

        return {
            "ok": True,
            "filename": display_name,
            "file_type": "image",
            "mode": "ocr_only",
            "width": width,
            "height": height,
            "extracted_text": cleaned,
            "char_count": len(cleaned),
            "status": "extracted",
            "message": f"Extracted {len(cleaned)} characters via Tesseract OCR (OCR-only mode).",
        }
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Stage 4: PDF Document Upload and Processing (PyMuPDF + Tesseract OCR)
# ---------------------------------------------------------------------------

ALLOWED_PDF_EXTENSIONS = {".pdf"}
ALLOWED_PDF_MIME_TYPES = {"application/pdf", "application/x-pdf"}
MAX_PDF_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_PDF_PAGES = 50
MAX_PDF_CONTEXT_CHARS = 8000


def validate_pdf_magic(file_bytes: bytes) -> bool:
    """Return True if file_bytes begins with the `%PDF-` magic header."""
    return bool(file_bytes) and file_bytes.startswith(b"%PDF-")


def process_uploaded_pdf(
    file_bytes: bytes,
    original_filename: str | None,
    user_id: int,
    content_type: str | None = None,
) -> dict:
    """
    Validate an uploaded PDF and extract text page-by-page using PyMuPDF,
    falling back to Tesseract OCR for scanned pages without native text.
    """
    display_name = os.path.basename(original_filename or "uploaded_document.pdf").strip() or "uploaded_document.pdf"
    ext = os.path.splitext(display_name)[1].lower()

    if ext not in ALLOWED_PDF_EXTENSIONS:
        raise UploadValidationError(
            f"Unsupported document format '{ext or 'none'}'. Only .pdf files are allowed.",
            status_code=400,
        )

    if content_type:
        mime = content_type.split(";")[0].strip().lower()
        if mime and mime not in ALLOWED_PDF_MIME_TYPES:
            raise UploadValidationError(
                f"Unsupported MIME type '{mime}'. Expected application/pdf.",
                status_code=400,
            )

    if not file_bytes:
        raise UploadValidationError("Uploaded PDF file is empty.", status_code=400)

    if len(file_bytes) > MAX_PDF_BYTES:
        raise UploadValidationError(
            f"PDF exceeds maximum allowed size of {MAX_PDF_BYTES // (1024 * 1024)} MB.",
            status_code=413,
        )

    if not validate_pdf_magic(file_bytes):
        raise UploadValidationError(
            "Uploaded file does not have a valid %PDF- header.",
            status_code=400,
        )

    user_tmp_dir = os.path.join(UPLOAD_TEMP_ROOT, f"user_{int(user_id)}")
    os.makedirs(user_tmp_dir, exist_ok=True)
    safe_name = f"{uuid.uuid4().hex}.pdf"
    temp_path = os.path.join(user_tmp_dir, safe_name)

    doc = None
    try:
        with open(temp_path, "wb") as f:
            f.write(file_bytes)

        try:
            doc = fitz.open(temp_path)
        except Exception as exc:
            raise UploadValidationError(
                "Uploaded file is not a valid or readable PDF.",
                status_code=400,
            ) from exc

        if doc.is_encrypted or getattr(doc, "needs_pass", False):
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "pdf",
                "mode": "pdf_text_and_ocr",
                "page_count": doc.page_count,
                "pages": [],
                "extracted_text": "",
                "char_count": 0,
                "truncated": False,
                "status": "encrypted",
                "message": "PDF is encrypted or password-protected and cannot be processed.",
            }

        page_count = doc.page_count
        if page_count == 0:
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "pdf",
                "mode": "pdf_text_and_ocr",
                "page_count": 0,
                "pages": [],
                "extracted_text": "",
                "char_count": 0,
                "truncated": False,
                "status": "empty",
                "message": "PDF contains no pages.",
            }

        if page_count > MAX_PDF_PAGES:
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "pdf",
                "mode": "pdf_text_and_ocr",
                "page_count": page_count,
                "pages": [],
                "extracted_text": "",
                "char_count": 0,
                "truncated": False,
                "status": "page_limit_exceeded",
                "message": f"PDF has {page_count} pages, exceeding the maximum limit of {MAX_PDF_PAGES} pages.",
            }

        pages_meta: list[dict] = []
        page_blocks: list[str] = []
        ocr_unavailable_pages = 0

        for page_idx in range(page_count):
            page_num = page_idx + 1
            page = doc.load_page(page_idx)
            native_text = (page.get_text("text") or "").strip()

            if native_text:
                pages_meta.append({
                    "page": page_num,
                    "method": "text",
                    "status": "extracted",
                    "char_count": len(native_text),
                })
                page_blocks.append(f"[Page {page_num}]\n{native_text}")
            else:
                pix = None
                try:
                    pix = page.get_pixmap(dpi=150)
                    img_bytes = pix.tobytes("png")
                finally:
                    pix = None

                ocr_res = process_uploaded_image(
                    file_bytes=img_bytes,
                    original_filename=f"page_{page_num}.png",
                    user_id=user_id,
                )
                ocr_status = ocr_res.get("status", "unreadable")
                if ocr_res.get("ok") and ocr_res.get("extracted_text"):
                    ocr_text = ocr_res["extracted_text"]
                    pages_meta.append({
                        "page": page_num,
                        "method": "ocr",
                        "status": "extracted",
                        "char_count": len(ocr_text),
                    })
                    page_blocks.append(f"[Page {page_num} (OCR)]\n{ocr_text}")
                else:
                    if ocr_status == "ocr_unavailable":
                        ocr_unavailable_pages += 1
                    pages_meta.append({
                        "page": page_num,
                        "method": "ocr",
                        "status": ocr_status,
                        "char_count": 0,
                    })

        combined_text = "\n\n".join(page_blocks).strip()
        if not combined_text:
            if ocr_unavailable_pages > 0:
                return {
                    "ok": False,
                    "filename": display_name,
                    "file_type": "pdf",
                    "mode": "pdf_text_and_ocr",
                    "page_count": page_count,
                    "pages": pages_meta,
                    "extracted_text": "",
                    "char_count": 0,
                    "truncated": False,
                    "status": "ocr_unavailable",
                    "message": "Tesseract OCR binary is not installed on the server. Cannot extract text from scanned PDF pages.",
                }
            return {
                "ok": False,
                "filename": display_name,
                "file_type": "pdf",
                "mode": "pdf_text_and_ocr",
                "page_count": page_count,
                "pages": pages_meta,
                "extracted_text": "",
                "char_count": 0,
                "status": "no_text_found",
                "message": "No readable text was detected in this PDF.",
            }

        truncated = False
        if len(combined_text) > MAX_PDF_CONTEXT_CHARS:
            truncated = True
            notice = f"\n\n[TRUNCATED: Extracted PDF text exceeded {MAX_PDF_CONTEXT_CHARS} character limit and was truncated.]"
            keep_len = max(0, MAX_PDF_CONTEXT_CHARS - len(notice))
            combined_text = combined_text[:keep_len].rstrip() + notice

        final_status = "truncated" if truncated else "extracted"
        msg = (
            f"Extracted {len(combined_text)} characters from {page_count} page(s) (truncated to fit context limit)."
            if truncated
            else f"Extracted {len(combined_text)} characters from {page_count} page(s)."
        )
        if ocr_unavailable_pages > 0:
            msg += f" ({ocr_unavailable_pages} scanned page(s) skipped: Tesseract OCR unavailable.)"

        return {
            "ok": True,
            "filename": display_name,
            "file_type": "pdf",
            "mode": "pdf_text_and_ocr",
            "page_count": page_count,
            "pages": pages_meta,
            "extracted_text": combined_text,
            "char_count": len(combined_text),
            "truncated": truncated,
            "status": final_status,
            "message": msg,
        }
    finally:
        if doc is not None:
            try:
                doc.close()
            except Exception:
                pass
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
