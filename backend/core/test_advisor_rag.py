"""
test_advisor_rag.py – Stage 2 tests for Text-Based RAG Chatbot.

Covers:
- Chunk building & deduplicated ChromaDB indexing
- Selected-analysis vs All My Analyses retrieval
- Follow-up conversation history & clearing
- Unavailable information / empty user handling
- Ollama disconnection & error handling (HTTP 503)
- Unauthorized analysis access & cross-user isolation (ChromaDB + chat history + API)
"""

import hashlib
import os
import tempfile
import unittest
from unittest.mock import patch

import chromadb
from fastapi.testclient import TestClient

from core import auth, database, rag_chat, rag_store
from main import app


def _deterministic_embed(texts: list[str]) -> list[list[float]]:
    """Lightweight deterministic 16-d embedding for isolated unit tests."""
    vecs = []
    for t in texts:
        h = hashlib.sha256(t.encode("utf-8")).digest()
        vecs.append([b / 255.0 for b in h[:16]])
    return vecs


def _sample_report(analysis_id: str, filename: str, encryption: str = "AES-GCM-16", dh: str = "Group 19 (ECP-256)"):
    return {
        "id": analysis_id,
        "filename": filename,
        "status": "completed",
        "pcap_metrics": {
            "packet_count": 12,
            "protocols_found": ["IKE", "ESP"],
            "vpn_mode_inferred": "Tunnel",
            "ike_version": "IKEv2",
            "encryption": encryption,
            "authentication": "Not Extracted",
            "key_exchange": dh,
            "beaconing_analysis": {
                "status": "ok",
                "verdict": "Normal: Aperiodic / Human Interactive Traffic",
                "anomaly_level": "LOW",
                "anomaly_score": 8.8,
                "beacon_detected": False,
                "estimated_interval_sec": 0.003,
                "jitter_sec": 0.68,
                "confidence_level": "MODERATE",
                "explanation": "No persistent periodic beaconing detected.",
                "insights": ["High inter-arrival time variance."],
            },
            "forensics_timeline": [
                {
                    "packet_no": 1,
                    "timestamp": "0.000000",
                    "stage": "IKE_SA_INIT",
                    "classification": "Observed",
                    "event": "IKEv2 SA_INIT Request",
                    "evidence": f"Observed {encryption} and {dh} in Packet #1",
                }
            ],
            "packets": [
                {
                    "number": 1,
                    "protocol": "ISAKMP",
                    "src": "10.0.0.1",
                    "dst": "10.0.0.2",
                    "length": 240,
                    "info": "IKE_SA_INIT request",
                }
            ],
        },
        "security_assessment": {
            "overall_risk_score": 3 if "3DES" in encryption else 0,
            "risk_level": "High" if "3DES" in encryption else "Informational",
            "score_explanation": "Evaluated 5 rules, skipped 1 rule.",
            "rules_evaluated": [
                {"rule": "Encryption Algorithm Strength", "observed_value": encryption, "status": "FAIL" if "3DES" in encryption else "PASS"}
            ],
            "rules_skipped": [
                {"rule": "Authentication Method", "reason": "Authentication method not extractable from capture."}
            ],
            "findings": [
                {
                    "title": "Weak Encryption Algorithm" if "3DES" in encryption else "Strong Encryption Algorithm",
                    "description": f"Observed encryption: {encryption}",
                    "severity": "High" if "3DES" in encryption else "Informational",
                    "recommendation": "Use AES-GCM-16." if "3DES" in encryption else "No action required.",
                    "evidence": f"Observed in IKE SA proposal: {encryption}",
                    "risk_contribution": 3 if "3DES" in encryption else 0,
                }
            ],
        },
        "ml_prediction": {
            "predicted_category": "CHAT",
            "confidence_score": 0.42,
            "model_status": "trained_model",
            "model_note": "Short capture (<30 packets).",
            "features_required_missing": [],
            "explainability": {
                "summary": "Driven by outbound IAT.",
                "top_contributing_factors": [
                    {"feature_name": "Min Outbound Interval", "observed_value": "0.003s", "impact_percentage": 50.0, "reason": "Burst cadence"}
                ],
            },
        },
    }


class TestAdvisorRAG(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = os.path.join(self.tmpdir.name, "test.db")
        self.chroma_dir = os.path.join(self.tmpdir.name, "chroma")

        self._orig_db_backend = database.db_backend
        self._orig_sqlite_path = database.SQLITE_DB_PATH
        database.db_backend = "sqlite"
        database.SQLITE_DB_PATH = self.db_path
        database.init_db()
        auth.init_auth_tables()
        rag_chat.init_advisor_tables()

        self.chroma_client = chromadb.EphemeralClient()
        self.collection = self.chroma_client.get_or_create_collection(
            f"test_rag_{self._testMethodName}"
        )

        # Create User A and User B
        auth.create_user("alice_rag", "Pass1234!")
        auth.create_user("bob_rag", "Pass1234!")
        self.user_a = auth.verify_user("alice_rag", "Pass1234!")["user_id"]
        self.user_b = auth.verify_user("bob_rag", "Pass1234!")["user_id"]
        self.token_a = auth.create_token(self.user_a, "alice_rag")
        self.token_b = auth.create_token(self.user_b, "bob_rag")

        # Save analyses
        self.rep_a1 = _sample_report("anl-alice-1", "alice_strong.pcap", "AES-GCM-16", "Group 19 (ECP-256)")
        self.rep_a2 = _sample_report("anl-alice-2", "alice_weak.pcap", "3DES-CBC", "Group 2 (1024-bit)")
        self.rep_b1 = _sample_report("anl-bob-1", "bob_secret.pcap", "DES-CBC", "Group 1 (768-bit)")
        database.save_analysis(self.rep_a1, user_id=self.user_a)
        database.save_analysis(self.rep_a2, user_id=self.user_a)
        database.save_analysis(self.rep_b1, user_id=self.user_b)

    def tearDown(self):
        database.db_backend = self._orig_db_backend
        database.SQLITE_DB_PATH = self._orig_sqlite_path
        self.chroma_client = None
        self.collection = None
        self.tmpdir.cleanup()

    def test_indexing_deduplication(self):
        first = rag_store.index_analysis_if_needed(
            self.rep_a1, user_id=self.user_a, collection=self.collection, embed_fn=_deterministic_embed
        )
        self.assertGreater(first, 0)
        second = rag_store.index_analysis_if_needed(
            self.rep_a1, user_id=self.user_a, collection=self.collection, embed_fn=_deterministic_embed
        )
        self.assertEqual(second, 0)

    def test_selected_analysis_and_all_analyses_retrieval(self):
        rag_store.ensure_user_analyses_indexed(
            user_id=self.user_a, analysis_id=None, collection=self.collection, embed_fn=_deterministic_embed
        )
        # Selected analysis scope
        chunks_single = rag_store.retrieve_relevant_chunks(
            user_id=self.user_a,
            query="Why is encryption marked weak?",
            analysis_id="anl-alice-2",
            collection=self.collection,
            embed_fn=_deterministic_embed,
        )
        self.assertTrue(len(chunks_single) > 0)
        self.assertTrue(all(c["metadata"]["analysis_id"] == "anl-alice-2" for c in chunks_single))
        self.assertTrue(all(c["metadata"]["user_id"] == self.user_a for c in chunks_single))

        # All My Analyses scope
        chunks_all = rag_store.retrieve_relevant_chunks(
            user_id=self.user_a,
            query="encryption",
            analysis_id=None,
            collection=self.collection,
            embed_fn=_deterministic_embed,
        )
        aids = {c["metadata"]["analysis_id"] for c in chunks_all}
        self.assertTrue(aids.issubset({"anl-alice-1", "anl-alice-2"}))
        self.assertNotIn("anl-bob-1", aids)

    def test_cross_user_isolation_and_unauthorized_access(self):
        rag_store.ensure_user_analyses_indexed(
            user_id=self.user_b, analysis_id="anl-bob-1", collection=self.collection, embed_fn=_deterministic_embed
        )
        # User A cannot index or retrieve Bob's analysis
        with self.assertRaises(PermissionError):
            rag_store.ensure_user_analyses_indexed(
                user_id=self.user_a, analysis_id="anl-bob-1", collection=self.collection, embed_fn=_deterministic_embed
            )

        # User A retrieval never returns Bob's chunks
        chunks_a = rag_store.retrieve_relevant_chunks(
            user_id=self.user_a, query="DES-CBC bob_secret", collection=self.collection, embed_fn=_deterministic_embed
        )
        self.assertEqual(chunks_a, [])

    def test_follow_up_history_and_clear_isolation(self):
        captured_prompts = []

        def fake_chat(msgs):
            captured_prompts.append(msgs)
            return f"Answer #{len(captured_prompts)} citing [anl-alice-1]."

        res1 = rag_chat.generate_rag_answer(
            user_id=self.user_a,
            message="Explain my encryption.",
            analysis_id="anl-alice-1",
            collection=self.collection,
            embed_fn=_deterministic_embed,
            chat_fn=fake_chat,
        )
        self.assertIn("Answer #1", res1["answer"])
        self.assertTrue(len(res1["references"]) >= 1)

        # Follow-up should include previous turn in messages sent to LLM
        rag_chat.generate_rag_answer(
            user_id=self.user_a,
            message="What about the DH group?",
            analysis_id="anl-alice-1",
            collection=self.collection,
            embed_fn=_deterministic_embed,
            chat_fn=fake_chat,
        )
        second_msgs = captured_prompts[1]
        roles = [m["role"] for m in second_msgs]
        self.assertEqual(roles, ["system", "user", "assistant", "user"])

        # Bob's history must remain empty even though Alice chatted
        self.assertEqual(rag_chat.get_chat_history(self.user_b, "anl-alice-1"), [])
        self.assertEqual(len(rag_chat.get_chat_history(self.user_a, "anl-alice-1")), 4)

        # Bob clearing his history does not affect Alice
        rag_chat.clear_chat_history(self.user_b, "anl-alice-1")
        self.assertEqual(len(rag_chat.get_chat_history(self.user_a, "anl-alice-1")), 4)

        rag_chat.clear_chat_history(self.user_a, "anl-alice-1")
        self.assertEqual(rag_chat.get_chat_history(self.user_a, "anl-alice-1"), [])

    def test_empty_user_unavailable_info(self):
        auth.create_user("empty_user", "Pass1234!")
        empty_id = auth.verify_user("empty_user", "Pass1234!")["user_id"]
        captured = []

        def fake_chat(msgs):
            captured.append(msgs)
            return "No PCAP analysis reports are available for your account yet."

        res = rag_chat.generate_rag_answer(
            user_id=empty_id,
            message="Explain my complete security report.",
            analysis_id=None,
            collection=self.collection,
            embed_fn=_deterministic_embed,
            chat_fn=fake_chat,
        )
        self.assertEqual(res["references"], [])
        self.assertIn("No PCAP analysis reports were found", captured[0][0]["content"])

    def test_api_endpoints_and_ollama_disconnection(self):
        client = TestClient(app)

        # Unauthenticated rejected
        r_unauth = client.get("/api/advisor/status")
        self.assertEqual(r_unauth.status_code, 401)

        # Ollama unreachable status
        with patch("core.rag_chat.httpx.Client") as mock_http:
            mock_http.return_value.__enter__.return_value.get.side_effect = OSError("Connection refused")
            r_status = client.get("/api/advisor/status", headers={"Authorization": f"Bearer {self.token_a}"})
            self.assertEqual(r_status.status_code, 200)
            self.assertFalse(r_status.json()["ollama_connected"])

        # Cross-user chat attempt via API returns 404
        r_forbidden = client.post(
            "/api/advisor/chat",
            json={"message": "Explain this report", "analysis_id": "anl-bob-1"},
            headers={"Authorization": f"Bearer {self.token_a}"},
        )
        self.assertEqual(r_forbidden.status_code, 404)

        # Ollama disconnection during chat returns 503
        with patch("core.rag_store.get_chroma_collection", return_value=self.collection), \
             patch("core.rag_store.embed_texts", side_effect=rag_store.OllamaEmbeddingError("Ollama offline")):
            r_offline = client.post(
                "/api/advisor/chat",
                json={"message": "Explain my risk score", "analysis_id": "anl-alice-1"},
                headers={"Authorization": f"Bearer {self.token_a}"},
            )
            self.assertEqual(r_offline.status_code, 503)


if __name__ == "__main__":
    unittest.main()


# ──────────────────────────────────────────────────────────────────────────────
# Stage 3 Tests – Image Upload & OCR (document_processor.py)
# ──────────────────────────────────────────────────────────────────────────────

import io
import struct
from unittest.mock import MagicMock, patch

from PIL import Image as PILImage


def _make_png_bytes(text: str = "IKEv2 AES-GCM-16") -> bytes:
    """Create a minimal valid 20×10 RGB PNG in memory."""
    buf = io.BytesIO()
    img = PILImage.new("RGB", (20, 10), color=(30, 60, 90))
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg_bytes() -> bytes:
    buf = io.BytesIO()
    img = PILImage.new("RGB", (20, 10), color=(10, 20, 30))
    img.save(buf, format="JPEG")
    return buf.getvalue()


class TestDocumentProcessor(unittest.TestCase):
    """Unit tests for core.document_processor.process_uploaded_image."""

    def setUp(self):
        from core import document_processor  # noqa: F401 – ensures importable
        self.dp = __import__("core.document_processor", fromlist=["process_uploaded_image",
                                                                   "UploadValidationError"])

    # ── 1. Valid PNG bytes → OCR extraction ──────────────────────────────────
    def test_valid_png_ocr_extracted(self):
        png = _make_png_bytes()
        with patch("pytesseract.image_to_string", return_value="IKEv2 AES-GCM-16"):
            result = self.dp.process_uploaded_image(
                file_bytes=png, original_filename="screen.png", user_id=1
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "extracted")
        self.assertIn("IKEv2", result["extracted_text"])
        self.assertEqual(result["file_type"], "image")
        self.assertEqual(result["mode"], "ocr_only")

    # ── 2. Oversized file → UploadValidationError (413) ──────────────────────
    def test_oversized_image_raises_413(self):
        big = b"\x00" * (11 * 1024 * 1024)  # 11 MB
        with self.assertRaises(self.dp.UploadValidationError) as ctx:
            self.dp.process_uploaded_image(
                file_bytes=big, original_filename="big.png", user_id=1
            )
        self.assertEqual(ctx.exception.status_code, 413)

    # ── 3. Invalid extension → UploadValidationError (400) ───────────────────
    def test_invalid_extension_raises_400(self):
        with self.assertRaises(self.dp.UploadValidationError) as ctx:
            self.dp.process_uploaded_image(
                file_bytes=b"\x00\x01\x02", original_filename="malware.exe", user_id=1
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Unsupported image format", str(ctx.exception))

    # ── 4. Valid extension but non-image bytes → UploadValidationError (400) ─
    def test_non_image_bytes_raises_400(self):
        with self.assertRaises(self.dp.UploadValidationError) as ctx:
            self.dp.process_uploaded_image(
                file_bytes=b"not an image at all", original_filename="fake.png", user_id=1
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not a valid", str(ctx.exception))

    # ── 5. Tesseract not found → status: "ocr_unavailable" ───────────────────
    def test_tesseract_not_found_returns_ocr_unavailable(self):
        import pytesseract as pyt
        png = _make_png_bytes()
        with patch("pytesseract.image_to_string",
                   side_effect=pyt.TesseractNotFoundError()):
            result = self.dp.process_uploaded_image(
                file_bytes=png, original_filename="screen.png", user_id=2
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "ocr_unavailable")
        self.assertEqual(result["extracted_text"], "")

    # ── 6. OCR returns empty string → status: "no_text_found" ────────────────
    def test_ocr_empty_returns_no_text_found(self):
        png = _make_png_bytes()
        with patch("pytesseract.image_to_string", return_value="   "):
            result = self.dp.process_uploaded_image(
                file_bytes=png, original_filename="blank.png", user_id=3
            )
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "no_text_found")

    # ── 7. attachment_context passes through generate_rag_answer ─────────────
    def test_attachment_context_appears_in_llm_messages(self):
        """The OCR extracted text must be injected into the system prompt
        wrapped in <untrusted_uploaded_document> tags."""
        import tempfile, chromadb
        tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = os.path.join(tmpdir.name, "test.db")
        try:
            from core import auth, database, rag_chat
            orig_db, orig_path = database.db_backend, database.SQLITE_DB_PATH
            database.db_backend = "sqlite"
            database.SQLITE_DB_PATH = db_path
            database.init_db()
            auth.init_auth_tables()
            rag_chat.init_advisor_tables()

            auth.create_user("attach_user", "Pass1234!")
            uid = auth.verify_user("attach_user", "Pass1234!")["user_id"]

            coll = chromadb.EphemeralClient().get_or_create_collection("attach_test")
            captured_msgs = []

            def fake_chat(msgs):
                captured_msgs.extend(msgs)
                return "Answer with attachment context."

            rag_chat.generate_rag_answer(
                user_id=uid,
                message="What does this screenshot show?",
                analysis_id=None,
                collection=coll,
                embed_fn=_deterministic_embed,
                chat_fn=fake_chat,
                attachment_context={
                    "source": "wireshark.png",
                    "extracted_text": "IKEv2 SA_INIT AES-GCM-16 Group19",
                },
            )

            system_content = captured_msgs[0]["content"]
            self.assertIn("<untrusted_uploaded_document>", system_content)
            self.assertIn("IKEv2 SA_INIT", system_content)

        finally:
            database.db_backend = orig_db
            database.SQLITE_DB_PATH = orig_path
            tmpdir.cleanup()

    # ── 8. Upload endpoint – unauthenticated → 401 ────────────────────────────
    def test_upload_endpoint_requires_auth(self):
        import tempfile, chromadb
        tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = os.path.join(tmpdir.name, "test.db")
        try:
            from core import auth, database, rag_chat
            orig_db, orig_path = database.db_backend, database.SQLITE_DB_PATH
            database.db_backend = "sqlite"
            database.SQLITE_DB_PATH = db_path
            database.init_db()
            auth.init_auth_tables()
            rag_chat.init_advisor_tables()

            client = TestClient(app)
            png = _make_png_bytes()
            r = client.post(
                "/api/advisor/upload",
                files={"file": ("screen.png", png, "image/png")},
            )
            self.assertEqual(r.status_code, 401)
        finally:
            database.db_backend = orig_db
            database.SQLITE_DB_PATH = orig_path
            tmpdir.cleanup()


class TestPdfDocumentProcessor(unittest.TestCase):
    """Stage 4 unit tests for core.document_processor.process_uploaded_pdf."""

    def setUp(self):
        import fitz
        from core import document_processor
        self.fitz = fitz
        self.dp = document_processor

    def _make_text_pdf(self, pages_text: list[str]) -> bytes:
        doc = self.fitz.open()
        for txt in pages_text:
            page = doc.new_page()
            if txt:
                page.insert_text((72, 72), txt)
        data = doc.tobytes()
        doc.close()
        return data

    def _make_scanned_pdf(self) -> bytes:
        doc = self.fitz.open()
        page = doc.new_page()
        page.insert_image(self.fitz.Rect(20, 20, 120, 80), stream=_make_png_bytes())
        data = doc.tobytes()
        doc.close()
        return data

    def _make_encrypted_pdf(self) -> bytes:
        doc = self.fitz.open()
        page = doc.new_page()
        page.insert_text((72, 72), "Secret IPsec config")
        data = doc.tobytes(
            encryption=self.fitz.PDF_ENCRYPT_AES_256,
            owner_pw="owner123",
            user_pw="user123",
        )
        doc.close()
        return data

    def test_text_pdf_preserves_page_numbers_and_cleans_temp(self):
        pdf_bytes = self._make_text_pdf([
            "IKEv2 proposal uses AES-GCM-16.",
            "Diffie-Hellman Group 19 observed.",
        ])
        user_tmp = os.path.join(self.dp.UPLOAD_TEMP_ROOT, "user_901")
        before = set(os.listdir(user_tmp)) if os.path.isdir(user_tmp) else set()

        res = self.dp.process_uploaded_pdf(pdf_bytes, "report.pdf", user_id=901, content_type="application/pdf")
        self.assertTrue(res["ok"])
        self.assertEqual(res["file_type"], "pdf")
        self.assertEqual(res["status"], "extracted")
        self.assertEqual(res["page_count"], 2)
        self.assertIn("[Page 1]", res["extracted_text"])
        self.assertIn("[Page 2]", res["extracted_text"])
        self.assertIn("AES-GCM-16", res["extracted_text"])
        self.assertIn("Group 19", res["extracted_text"])

        after = set(os.listdir(user_tmp)) if os.path.isdir(user_tmp) else set()
        self.assertEqual(before, after)

    def test_scanned_pdf_uses_ocr_fallback(self):
        pdf_bytes = self._make_scanned_pdf()
        with patch("pytesseract.image_to_string", return_value="ESP Tunnel Mode Observed"):
            res = self.dp.process_uploaded_pdf(pdf_bytes, "scan.pdf", user_id=902, content_type="application/pdf")
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "extracted")
        self.assertIn("[Page 1 (OCR)]", res["extracted_text"])
        self.assertIn("ESP Tunnel Mode Observed", res["extracted_text"])

    def test_scanned_pdf_ocr_unavailable(self):
        import pytesseract
        pdf_bytes = self._make_scanned_pdf()
        with patch("pytesseract.image_to_string", side_effect=pytesseract.TesseractNotFoundError()):
            res = self.dp.process_uploaded_pdf(pdf_bytes, "scan.pdf", user_id=903)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "ocr_unavailable")

    def test_encrypted_pdf_handled_gracefully(self):
        pdf_bytes = self._make_encrypted_pdf()
        res = self.dp.process_uploaded_pdf(pdf_bytes, "locked.pdf", user_id=904)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "encrypted")

    def test_corrupted_invalid_mime_and_oversized_pdf(self):
        with self.assertRaises(self.dp.UploadValidationError) as ctx_ext:
            self.dp.process_uploaded_pdf(b"%PDF-1.4...", "not_a_pdf.txt", user_id=905)
        self.assertEqual(ctx_ext.exception.status_code, 400)

        with self.assertRaises(self.dp.UploadValidationError) as ctx_mime:
            self.dp.process_uploaded_pdf(b"%PDF-1.4...", "doc.pdf", user_id=905, content_type="text/plain")
        self.assertEqual(ctx_mime.exception.status_code, 400)

        with self.assertRaises(self.dp.UploadValidationError) as ctx_magic:
            self.dp.process_uploaded_pdf(b"NOT_PDF_BYTES", "doc.pdf", user_id=905)
        self.assertEqual(ctx_magic.exception.status_code, 400)

        with self.assertRaises(self.dp.UploadValidationError) as ctx_corrupt:
            self.dp.process_uploaded_pdf(b"%PDF-1.4\ncorrupt-body", "corrupt.pdf", user_id=905)
        self.assertEqual(ctx_corrupt.exception.status_code, 400)

        oversized = b"%PDF-1.4" + (b"0" * (self.dp.MAX_PDF_BYTES + 1))
        with self.assertRaises(self.dp.UploadValidationError) as ctx_size:
            self.dp.process_uploaded_pdf(oversized, "huge.pdf", user_id=905)
        self.assertEqual(ctx_size.exception.status_code, 413)

    def test_page_limit_exceeded_rejected(self):
        pdf_bytes = self._make_text_pdf([f"Page {i}" for i in range(1, 52)])
        res = self.dp.process_uploaded_pdf(pdf_bytes, "51pages.pdf", user_id=906)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"], "page_limit_exceeded")
        self.assertEqual(res["page_count"], 51)

    def test_context_truncation_indicated(self):
        # Insert multiple lines per page so PyMuPDF extracts >8000 chars total
        page_text = "\n".join(f"Line {i}: IKEv2 AES-GCM-16 DH-Group-19" for i in range(60))
        long_pages = [page_text for _ in range(5)]
        pdf_bytes = self._make_text_pdf(long_pages)
        res = self.dp.process_uploaded_pdf(pdf_bytes, "long.pdf", user_id=907)
        self.assertTrue(res["ok"])
        self.assertTrue(res["truncated"])
        self.assertEqual(res["status"], "truncated")
        self.assertIn("[TRUNCATED:", res["extracted_text"])

    def test_pdf_attachment_page_references_reach_llm(self):
        tmpdir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        db_path = os.path.join(tmpdir.name, "test.db")
        orig_db, orig_path = database.db_backend, database.SQLITE_DB_PATH
        try:
            database.db_backend = "sqlite"
            database.SQLITE_DB_PATH = db_path
            database.init_db()
            auth.init_auth_tables()
            rag_chat.init_advisor_tables()
            auth.create_user("pdf_user", "Pass1234!")
            uid = auth.verify_user("pdf_user", "Pass1234!")["user_id"]
            client = chromadb.EphemeralClient()
            coll = client.get_or_create_collection("test_pdf_ctx")

            captured_msgs = []

            def fake_chat(msgs):
                captured_msgs.extend(msgs)
                return "Page 2 shows Group 19."

            rag_chat.generate_rag_answer(
                user_id=uid,
                message="Which page mentions Group 19?",
                analysis_id=None,
                collection=coll,
                embed_fn=_deterministic_embed,
                chat_fn=fake_chat,
                attachment_context={
                    "filename": "audit.pdf",
                    "file_type": "pdf",
                    "extracted_text": "[Page 1]\nIKEv2\n\n[Page 2]\nGroup 19",
                },
            )
            sys_msg = captured_msgs[0]["content"]
            self.assertIn('filename="audit.pdf" type="pdf"', sys_msg)
            self.assertIn("[Page 2]", sys_msg)
        finally:
            database.db_backend = orig_db
            database.SQLITE_DB_PATH = orig_path
            tmpdir.cleanup()


class TestGroqDualBackend(unittest.TestCase):
    """Tests for Groq Cloud backend + Ollama fallback + hash embedding fallback."""

    def test_status_selects_groq_when_api_key_set(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_123", "PYTHON_ENV": "production"}, clear=False):
            st = rag_chat.check_advisor_status()
        self.assertEqual(st["backend"], "groq")
        self.assertTrue(st["groq_connected"])
        self.assertTrue(st["chat_model_available"])
        self.assertTrue(st["embed_model_available"])
        self.assertEqual(st["embed_model"], "local-hash-v1")

    def test_call_groq_chat_uses_openai_compatible_endpoint(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Groq response for AES-GCM-16."}}]
        }
        mock_resp.raise_for_status.return_value = None

        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_123"}, clear=False), \
             patch("core.rag_chat.httpx.Client") as mock_client:
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            ans = rag_chat.call_groq_chat([{"role": "user", "content": "Explain encryption"}])

        self.assertEqual(ans, "Groq response for AES-GCM-16.")
        call_args = mock_client.return_value.__enter__.return_value.post.call_args
        self.assertIn("/chat/completions", call_args[0][0])
        self.assertEqual(call_args[1]["headers"]["Authorization"], "Bearer gsk_test_123")

    def test_hash_embed_fallback_in_production_groq_mode(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "gsk_test_123", "PYTHON_ENV": "production"}, clear=False):
            vecs = rag_store.embed_texts(["IKEv2 AES-GCM-16", "Diffie-Hellman Group 19"])
        self.assertEqual(len(vecs), 2)
        self.assertEqual(len(vecs[0]), 384)


if __name__ == "__main__":
    unittest.main()