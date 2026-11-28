"""
rag_store.py – User-scoped ChromaDB vector store and Ollama embedding client
for the IPsec VPN Analyzer RAG Security Assistant.

Strict isolation:
- Every indexed chunk carries integer `user_id` and string `analysis_id` metadata.
- Every ChromaDB query filters strictly by `user_id` (and `analysis_id` when scoped).
- Indexing is deduplicated by `(user_id, analysis_id)` + `content_hash` to avoid
  repeatedly embedding unchanged reports.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Callable, Optional

import chromadb
import httpx

from core.database import (
    _infer_affected_parameter,
    _make_deterministic_finding_id,
    get_all_analyses,
    get_analysis_by_id,
)

logger = logging.getLogger(__name__)

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
OLLAMA_EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "nomic-embed-text")
CHROMA_PERSIST_DIR = os.environ.get(
    "CHROMA_PERSIST_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "chroma_db"),
)
COLLECTION_NAME = "ipsec_analysis_rag_v1"
HASH_COLLECTION_NAME = "ipsec_analysis_rag_hash_v1"

_chroma_client: Optional[chromadb.PersistentClient] = None
_hash_vectorizer = None


class OllamaEmbeddingError(RuntimeError):
    """Raised when Ollama embedding generation fails or Ollama is unreachable."""


def _hash_embed_texts(texts: list[str], n_features: int = 384) -> list[list[float]]:
    """Zero-dependency local L2-normalized hashing embeddings via scikit-learn."""
    if not texts:
        return []
    global _hash_vectorizer
    if _hash_vectorizer is None:
        from sklearn.feature_extraction.text import HashingVectorizer

        _hash_vectorizer = HashingVectorizer(
            n_features=n_features,
            ngram_range=(1, 2),
            norm="l2",
            alternate_sign=True,
            lowercase=True,
        )
    matrix = _hash_vectorizer.transform(texts)
    return matrix.toarray().tolist()


def is_ollama_reachable(base_url: str | None = None, timeout: float = 0.8) -> bool:
    """Fast check to see if local Ollama is reachable (skipped in production)."""
    if os.environ.get("PYTHON_ENV", "").strip().lower() == "production":
        return False
    url = (base_url or OLLAMA_BASE_URL).rstrip("/")
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"{url}/api/tags")
            return resp.status_code == 200
    except Exception:
        return False


def _use_hash_fallback() -> bool:
    """
    Use local scikit-learn hashing embeddings when:
    - EMBED_BACKEND=hash, OR
    - GROQ_API_KEY is set and Ollama is not reachable (e.g. Render cloud).
    """
    if os.environ.get("EMBED_BACKEND", "").strip().lower() == "hash":
        return True
    if os.environ.get("GROQ_API_KEY", "").strip():
        return not is_ollama_reachable()
    return False


def get_chroma_collection(persist_dir: str | None = None, collection_name: str | None = None):
    """Return (and lazily initialize) the persistent ChromaDB collection."""
    global _chroma_client
    target_dir = persist_dir or CHROMA_PERSIST_DIR
    target_name = collection_name or COLLECTION_NAME
    if persist_dir is not None:
        client = chromadb.PersistentClient(path=target_dir)
        return client.get_or_create_collection(name=target_name)

    if _chroma_client is None:
        os.makedirs(target_dir, exist_ok=True)
        _chroma_client = chromadb.PersistentClient(path=target_dir)
    return _chroma_client.get_or_create_collection(name=target_name)


def embed_texts(texts: list[str], base_url: str | None = None, model: str | None = None) -> list[list[float]]:
    """
    Generate vector embeddings.
    Uses local Ollama /api/embed by default, or falls back to local scikit-learn
    hashing embeddings when EMBED_BACKEND=hash or Groq mode is active without Ollama.
    """
    if not texts:
        return []
    if _use_hash_fallback():
        return _hash_embed_texts(texts)

    url = (base_url or OLLAMA_BASE_URL).rstrip("/")
    embed_model = model or OLLAMA_EMBED_MODEL

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{url}/api/embed",
                json={"model": embed_model, "input": texts},
            )
            if resp.status_code == 404:
                # Fallback for older Ollama versions using /api/embeddings
                embeddings = []
                for t in texts:
                    r2 = client.post(
                        f"{url}/api/embeddings",
                        json={"model": embed_model, "prompt": t},
                    )
                    r2.raise_for_status()
                    embeddings.append(r2.json()["embedding"])
                return embeddings

            resp.raise_for_status()
            data = resp.json()
            embeddings = data.get("embeddings")
            if not isinstance(embeddings, list) or len(embeddings) != len(texts):
                raise OllamaEmbeddingError("Invalid embedding response from Ollama.")
            return embeddings
    except httpx.HTTPError as exc:
        raise OllamaEmbeddingError(
            f"Unable to generate embeddings via Ollama ({embed_model}): {exc}"
        ) from exc


def _compute_report_hash(report: dict) -> str:
    """Stable hash of the report fields used for RAG indexing."""
    relevant = {
        "id": report.get("id"),
        "filename": report.get("filename"),
        "pcap_metrics": report.get("pcap_metrics"),
        "security_assessment": report.get("security_assessment"),
        "ml_prediction": report.get("ml_prediction"),
    }
    raw = json.dumps(relevant, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def build_analysis_chunks(report: dict, user_id: int) -> list[dict]:
    """
    Convert an AnalysisReport dict into grounded, citation-preserving text chunks.
    Never sends raw/entire PCAP blobs; caps packet samples to concise summaries.
    """
    analysis_id = str(report.get("id") or "")
    filename = str(report.get("filename") or "unknown.pcap")
    content_hash = _compute_report_hash(report)

    pm = report.get("pcap_metrics") if isinstance(report.get("pcap_metrics"), dict) else {}
    sa = report.get("security_assessment") if isinstance(report.get("security_assessment"), dict) else {}
    ml = report.get("ml_prediction") if isinstance(report.get("ml_prediction"), dict) else {}

    chunks: list[dict] = []

    def add_chunk(chunk_type: str, idx: int, text: str, finding_id: str = "", packet_nums: list[str] | None = None):
        pkt_csv = ",".join(str(p) for p in (packet_nums or []) if str(p).strip())[:500]
        chunks.append({
            "id": f"u{int(user_id)}_a{analysis_id}_{chunk_type}_{idx}",
            "text": text.strip(),
            "metadata": {
                "user_id": int(user_id),
                "analysis_id": analysis_id,
                "filename": filename,
                "chunk_type": chunk_type,
                "finding_id": finding_id,
                "packet_numbers": pkt_csv,
                "content_hash": content_hash,
            },
        })

    # 1. Overview & Cryptographic Parameters
    protocols = ", ".join(pm.get("protocols_found") or []) or "Unavailable"
    overview_text = (
        f"[Analysis {analysis_id} | File: {filename}] Overview & Cryptographic Parameters\n"
        f"- Packet Count (Observed): {pm.get('packet_count', 'Unavailable')}\n"
        f"- Protocols Found (Observed): {protocols}\n"
        f"- IKE Version (Observed): {pm.get('ike_version') or 'Not Extracted / Unavailable'}\n"
        f"- VPN Mode (Inferred from packet characteristics): {pm.get('vpn_mode_inferred') or 'Unavailable'}\n"
        f"- Encryption Algorithm (Observed): {pm.get('encryption') or 'Not Extracted / Unavailable'}\n"
        f"- Authentication Method (Observed): {pm.get('authentication') or 'Not Extracted / Unavailable'}\n"
        f"- Key Exchange / DH Group (Observed): {pm.get('key_exchange') or 'Not Extracted / Unavailable'}\n"
    )
    add_chunk("overview_crypto", 0, overview_text)

    # 2. Risk Assessment & Rules (Evaluated + Skipped)
    rules_eval = sa.get("rules_evaluated") or []
    rules_skip = sa.get("rules_skipped") or []
    eval_lines = [
        f"  * {r.get('rule')}: observed={r.get('observed_value', 'N/A')}, status={r.get('status', 'N/A')}"
        for r in rules_eval if isinstance(r, dict)
    ]
    skip_lines = [
        f"  * {r.get('rule')} (SKIPPED - Information Unavailable): {r.get('reason', 'Required parameter not observable')}"
        for r in rules_skip if isinstance(r, dict)
    ]
    risk_text = (
        f"[Analysis {analysis_id} | File: {filename}] Risk Assessment & Security Rules\n"
        f"- Overall Risk Score: {sa.get('overall_risk_score', 0)}\n"
        f"- Risk Level: {sa.get('risk_level', 'Unknown')}\n"
        f"- Score Explanation: {sa.get('score_explanation') or 'Unavailable'}\n"
        f"  (Note: A risk score of 0 does NOT guarantee the VPN is fully secure; skipped rules are not evaluated.)\n"
        f"- Rules Evaluated ({len(eval_lines)}):\n" + ("\n".join(eval_lines) or "  None") + "\n"
        f"- Rules Skipped ({len(skip_lines)}):\n" + ("\n".join(skip_lines) or "  None")
    )
    add_chunk("risk_assessment", 0, risk_text)

    # 3. Security Findings (preserving deterministic Finding IDs)
    findings = sa.get("findings") if isinstance(sa.get("findings"), list) else []
    seen_ids: dict[str, int] = {}
    for idx, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        title = f.get("title") or "Security Finding"
        evidence = f.get("evidence") or ""
        affected = _infer_affected_parameter(title, evidence)
        rule_or_title = f.get("rule_id") or f.get("rule") or title
        base_id = f.get("finding_id") or _make_deterministic_finding_id(
            analysis_id, str(rule_or_title), affected, evidence
        )
        occ = seen_ids.get(base_id, 0) + 1
        seen_ids[base_id] = occ
        finding_id = base_id if occ == 1 else f"{base_id}-{occ}"

        obs_type = "Inferred" if "inferred" in evidence.lower() or "inferred" in title.lower() else "Observed"
        f_text = (
            f"[Analysis {analysis_id} | File: {filename} | Finding {finding_id}] {title}\n"
            f"- Severity: {f.get('severity', 'Informational')}\n"
            f"- Observation Type: {obs_type}\n"
            f"- Affected Parameter: {affected}\n"
            f"- Risk Contribution: {f.get('risk_contribution', 0)}\n"
            f"- Description: {f.get('description') or ''}\n"
            f"- Evidence: {evidence or 'None recorded'}\n"
            f"- Recommendation: {f.get('recommendation') or 'None recorded'}"
        )
        add_chunk("finding", idx, f_text, finding_id=finding_id)

    # 4. Beaconing & Behavioral Analysis
    beaconing = pm.get("beaconing_analysis") if isinstance(pm.get("beaconing_analysis"), dict) else {}
    if beaconing:
        insights = "; ".join(beaconing.get("insights") or [])
        beacon_text = (
            f"[Analysis {analysis_id} | File: {filename}] Beaconing & Behavioral Timing Analysis (Inferred)\n"
            f"- Status: {beaconing.get('status', 'Unavailable')}\n"
            f"- Verdict: {beaconing.get('verdict', 'Unavailable')}\n"
            f"- Anomaly Level: {beaconing.get('anomaly_level', 'Unavailable')}\n"
            f"- Anomaly Score: {beaconing.get('anomaly_score', 'Unavailable')}\n"
            f"- Beacon Detected: {beaconing.get('beacon_detected', False)}\n"
            f"- Estimated Interval (sec): {beaconing.get('estimated_interval_sec', 'Unavailable')}\n"
            f"- Jitter (sec): {beaconing.get('jitter_sec', 'Unavailable')}\n"
            f"- Confidence Level: {beaconing.get('confidence_level', 'Unavailable')}\n"
            f"- Explanation: {beaconing.get('explanation') or ''}\n"
            f"- Insights: {insights or 'None'}\n"
            f"  (Note: Periodic timing is a behavioral indicator and may represent legitimate VPN keep-alives, not confirmed C2.)"
        )
        add_chunk("beaconing", 0, beacon_text)

    # 5. ML Predictions & Explainability
    if ml:
        expl = ml.get("explainability") if isinstance(ml.get("explainability"), dict) else {}
        factors = expl.get("top_contributing_factors") or []
        factor_lines = []
        for fc in factors:
            if isinstance(fc, dict):
                factor_lines.append(
                    f"  * {fc.get('feature_name', fc.get('feature_key', 'Feature'))}: "
                    f"observed={fc.get('observed_value', 'N/A')}, "
                    f"impact={fc.get('impact_percentage', 'N/A')}%, "
                    f"reason={fc.get('reason', '')}"
                )
            else:
                factor_lines.append(f"  * {fc}")
        missing_feats = ", ".join(ml.get("features_required_missing") or []) or "None"
        ml_text = (
            f"[Analysis {analysis_id} | File: {filename}] ML Traffic Classification & Explainability (Inferred)\n"
            f"- Predicted Category: {ml.get('predicted_category', 'Not Applicable')}\n"
            f"- Confidence Score: {ml.get('confidence_score', 'Unavailable')}\n"
            f"- Model Status: {ml.get('model_status', 'Unavailable')}\n"
            f"- Model Note / Limitations: {ml.get('model_note') or 'None'}\n"
            f"- Missing Features: {missing_feats}\n"
            f"- Explainability Summary: {expl.get('summary') or 'Unavailable'}\n"
            f"- Top Contributing Factors:\n" + ("\n".join(factor_lines) or "  None") + "\n"
            f"  (Note: ML traffic category is statistical similarity to training flows, never proof of an attack.)"
        )
        add_chunk("ml_explainability", 0, ml_text)

    # 6. Network Forensics Timeline (preserving packet numbers)
    timeline = pm.get("forensics_timeline") if isinstance(pm.get("forensics_timeline"), list) else []
    batch_size = 12
    for b_idx in range(0, len(timeline), batch_size):
        batch = timeline[b_idx:b_idx + batch_size]
        lines = []
        pkt_nums = []
        for ev in batch:
            if not isinstance(ev, dict):
                continue
            pno = ev.get("packet_no") or ev.get("packet_number") or ev.get("frame_number")
            if pno is not None:
                pkt_nums.append(str(pno))
            lines.append(
                f"  * Packet #{pno if pno is not None else 'N/A'} | t={ev.get('timestamp', 'N/A')} | "
                f"Stage={ev.get('stage', 'N/A')} | [{ev.get('classification', 'Observed')}] "
                f"{ev.get('event', '')} — Evidence: {ev.get('evidence', '')}"
            )
        if lines:
            tl_text = (
                f"[Analysis {analysis_id} | File: {filename}] Network Forensics Timeline (Events {b_idx + 1}-{b_idx + len(lines)})\n"
                + "\n".join(lines)
            )
            add_chunk("forensics_timeline", b_idx // batch_size, tl_text, packet_nums=pkt_nums)

    # 7. Packet-Level Evidence (bounded summary, max 80 packets, batches of 20)
    packets = pm.get("packets") if isinstance(pm.get("packets"), list) else []
    capped_packets = packets[:80]
    pkt_batch = 20
    for p_idx in range(0, len(capped_packets), pkt_batch):
        batch = capped_packets[p_idx:p_idx + pkt_batch]
        lines = []
        pkt_nums = []
        for pk in batch:
            if not isinstance(pk, dict):
                continue
            pno = pk.get("number") or pk.get("packet_no") or pk.get("frame_number")
            if pno is not None:
                pkt_nums.append(str(pno))
            lines.append(
                f"  * Packet #{pno if pno is not None else '?'} | {pk.get('protocol', '?')} | "
                f"{pk.get('src', '?')} -> {pk.get('dst', '?')} | len={pk.get('length', '?')} | {pk.get('info', '')}"
            )
        if lines:
            pkt_text = (
                f"[Analysis {analysis_id} | File: {filename}] Packet-Level Evidence (Packets {p_idx + 1}-{p_idx + len(lines)} of {len(packets)})\n"
                + "\n".join(lines)
            )
            add_chunk("packets", p_idx // pkt_batch, pkt_text, packet_nums=pkt_nums)

    return chunks


def index_analysis_if_needed(
    report: dict,
    user_id: int,
    collection=None,
    embed_fn: Optional[Callable[[list[str]], list[list[float]]]] = None,
) -> int:
    """
    Index an analysis report into ChromaDB for `user_id` if not already indexed
    with the same content_hash. Returns number of chunks upserted (0 if skipped).
    """
    analysis_id = str(report.get("id") or "")
    if not analysis_id:
        return 0

    col = collection if collection is not None else get_chroma_collection(
        collection_name=(HASH_COLLECTION_NAME if _use_hash_fallback() else COLLECTION_NAME)
    )
    content_hash = _compute_report_hash(report)

    existing = col.get(
        where={"$and": [{"user_id": int(user_id)}, {"analysis_id": analysis_id}]},
        include=["metadatas"],
    )
    existing_ids = existing.get("ids") or []
    existing_metas = existing.get("metadatas") or []

    if existing_ids and existing_metas and all(
        isinstance(m, dict) and m.get("content_hash") == content_hash for m in existing_metas
    ):
        return 0

    if existing_ids:
        col.delete(ids=existing_ids)

    chunks = build_analysis_chunks(report, user_id=int(user_id))
    if not chunks:
        return 0

    embedder = embed_fn or embed_texts
    texts = [c["text"] for c in chunks]
    embeddings = embedder(texts)

    col.upsert(
        ids=[c["id"] for c in chunks],
        documents=texts,
        metadatas=[c["metadata"] for c in chunks],
        embeddings=embeddings,
    )
    return len(chunks)


def ensure_user_analyses_indexed(
    user_id: int,
    analysis_id: str | None = None,
    collection=None,
    embed_fn: Optional[Callable[[list[str]], list[list[float]]]] = None,
) -> list[str]:
    """
    Ensure either the selected analysis (owned by user_id) or all analyses owned
    by user_id are indexed in ChromaDB.
    Raises PermissionError if analysis_id is specified but not owned/found for user_id.
    """
    col = collection if collection is not None else get_chroma_collection(
        collection_name=(HASH_COLLECTION_NAME if _use_hash_fallback() else COLLECTION_NAME)
    )
    indexed_ids: list[str] = []

    if analysis_id:
        report = get_analysis_by_id(analysis_id, user_id=user_id)
        if report is None:
            raise PermissionError("Analysis not found or access denied.")
        index_analysis_if_needed(report, user_id=user_id, collection=col, embed_fn=embed_fn)
        indexed_ids.append(str(analysis_id))
        return indexed_ids

    analyses = get_all_analyses(user_id=user_id)
    for row in analyses:
        aid = str(row.get("id") or "")
        if not aid:
            continue
        # Fast check before loading full_result
        existing = col.get(
            where={"$and": [{"user_id": int(user_id)}, {"analysis_id": aid}]},
            limit=1,
            include=[],
        )
        if existing.get("ids"):
            indexed_ids.append(aid)
            continue
        report = get_analysis_by_id(aid, user_id=user_id)
        if report is not None:
            index_analysis_if_needed(report, user_id=user_id, collection=col, embed_fn=embed_fn)
            indexed_ids.append(aid)

    return indexed_ids


def retrieve_relevant_chunks(
    user_id: int,
    query: str,
    analysis_id: str | None = None,
    top_k: int = 8,
    collection=None,
    embed_fn: Optional[Callable[[list[str]], list[list[float]]]] = None,
) -> list[dict]:
    """
    Retrieve top-k relevant chunks strictly scoped to `user_id`
    (and `analysis_id` when provided).
    """
    col = collection if collection is not None else get_chroma_collection(
        collection_name=(HASH_COLLECTION_NAME if _use_hash_fallback() else COLLECTION_NAME)
    )
    where_filter: dict = (
        {"$and": [{"user_id": int(user_id)}, {"analysis_id": str(analysis_id)}]}
        if analysis_id
        else {"user_id": int(user_id)}
    )

    # Check how many matching documents exist so n_results never exceeds count
    matching = col.get(where=where_filter, include=[])
    total_available = len(matching.get("ids") or [])
    if total_available == 0:
        return []

    n_results = min(max(1, top_k), total_available)
    embedder = embed_fn or embed_texts
    query_embedding = embedder([query])[0]

    res = col.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        where=where_filter,
        include=["documents", "metadatas", "distances"],
    )

    docs = (res.get("documents") or [[]])[0]
    metas = (res.get("metadatas") or [[]])[0]
    dists = (res.get("distances") or [[]])[0]

    results = []
    for doc, meta, dist in zip(docs, metas, dists):
        results.append({
            "text": doc,
            "metadata": meta or {},
            "distance": dist,
        })

    # If a specific analysis is selected, guarantee overview_crypto & risk_assessment
    # are present in context so summary/overview questions never miss core facts.
    if analysis_id:
        present_types = {r["metadata"].get("chunk_type") for r in results}
        for core_type in ("overview_crypto", "risk_assessment"):
            if core_type not in present_types:
                core = col.get(
                    where={
                        "$and": [
                            {"user_id": int(user_id)},
                            {"analysis_id": str(analysis_id)},
                            {"chunk_type": core_type},
                        ]
                    },
                    limit=1,
                    include=["documents", "metadatas"],
                )
                c_docs = core.get("documents") or []
                c_metas = core.get("metadatas") or []
                if c_docs:
                    results.insert(0, {
                        "text": c_docs[0],
                        "metadata": c_metas[0] if c_metas else {},
                        "distance": 0.0,
                    })

    return results
