import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Sparkles, Send, Trash2, RefreshCw, Loader2,
  AlertTriangle, CheckCircle2, XCircle, FileText,
  ArrowRight, Shield, MessageSquare, RotateCcw,
  Paperclip, X as XIcon, Image as ImageIcon,
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate } from '../lib/utils';

const ALLOWED_IMAGE_EXTS = new Set(['.jpg', '.jpeg', '.png', '.webp']);
const ALLOWED_PDF_EXTS = new Set(['.pdf']);

const SUGGESTED_QUESTIONS = ['Explain my complete security report.',
  'Why is my encryption marked weak?',
  'Why is my Diffie-Hellman group considered weak?',
  'Explain my risk score.',
  'Why were some security rules skipped?',
  'What does this packet show?',
  'Explain my beaconing analysis.',
  'What should I fix first?',
];

// Lightweight, safe markdown renderer (headings, bold, inline code, lists)
function renderInline(text) {
  const parts = String(text).split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return parts.map((part, idx) => {
    if (part.startsWith('**') && part.endsWith('**') && part.length > 4) {
      return <strong key={idx}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`') && part.length > 2) {
      return (
        <code
          key={idx}
          style={{
            fontFamily: 'monospace',
            fontSize: '0.9em',
            padding: '1px 5px',
            borderRadius: 4,
            backgroundColor: 'var(--bg-card)',
            border: '1px solid var(--border)',
          }}
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    return <span key={idx}>{part}</span>;
  });
}

function MarkdownBlock({ content }) {
  const lines = String(content || '').split('\n');
  const elements = [];
  let listItems = [];
  let tableRows = [];

  const flushList = (keyPrefix) => {
    if (listItems.length > 0) {
      elements.push(
        <ul key={`${keyPrefix}-ul`} style={{ margin: '0.35rem 0', paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {listItems.map((item, idx) => (
            <li key={idx} style={{ fontSize: 13, lineHeight: 1.55 }}>{renderInline(item)}</li>
          ))}
        </ul>
      );
      listItems = [];
    }
  };

  const flushTable = (keyPrefix) => {
    if (tableRows.length === 0) return;
    const parseRow = (r) => r.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
    const isSep = (r) => /^\|?[\s:-]+(\|[\s:-]+)+\|?$/.test(r);
    const nonSep = tableRows.filter((r) => !isSep(r));
    if (nonSep.length > 0) {
      const header = parseRow(nonSep[0]);
      const body = nonSep.slice(1).map(parseRow);
      elements.push(
        <div key={`${keyPrefix}-tbl`} style={{ overflowX: 'auto', margin: '0.5rem 0' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, border: '1px solid var(--border)', borderRadius: 6 }}>
            <thead>
              <tr style={{ backgroundColor: 'var(--bg-muted, rgba(148,163,184,0.12))' }}>
                {header.map((cell, cIdx) => (
                  <th key={cIdx} style={{ textAlign: 'left', padding: '6px 10px', borderBottom: '1px solid var(--border)', borderRight: '1px solid var(--border)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {renderInline(cell)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {body.map((row, rIdx) => (
                <tr key={rIdx} style={{ borderBottom: '1px solid var(--border)' }}>
                  {row.map((cell, cIdx) => (
                    <td key={cIdx} style={{ padding: '6px 10px', borderRight: '1px solid var(--border)', color: 'var(--text-primary)', verticalAlign: 'top', lineHeight: 1.45 }}>
                      {renderInline(cell)}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    }
    tableRows = [];
  };

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (!line) {
      flushList(idx);
      flushTable(idx);
      return;
    }
    if (line.startsWith('|') && line.includes('|', 1)) {
      flushList(idx);
      tableRows.push(line);
      return;
    }
    flushTable(idx);

    if (/^(-{3,}|\*{3,})$/.test(line)) {
      flushList(idx);
      elements.push(<hr key={idx} style={{ border: 'none', borderTop: '1px solid var(--border)', margin: '0.6rem 0' }} />);
    } else if (line.startsWith('### ')) {
      flushList(idx);
      elements.push(
        <h4 key={idx} style={{ margin: '0.5rem 0 0.25rem', fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
          {renderInline(line.slice(4))}
        </h4>
      );
    } else if (line.startsWith('## ') || line.startsWith('# ')) {
      flushList(idx);
      const text = line.replace(/^#{1,2}\s+/, '');
      elements.push(
        <h3 key={idx} style={{ margin: '0.5rem 0 0.25rem', fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
          {renderInline(text)}
        </h3>
      );
    } else if (/^[-*•]\s+/.test(line) || /^\d+\.\s+/.test(line)) {
      listItems.push(line.replace(/^([-*•]|\d+\.)\s+/, ''));
    } else {
      flushList(idx);
      elements.push(
        <p key={idx} style={{ margin: '0.25rem 0', fontSize: 13, lineHeight: 1.6, color: 'var(--text-primary)' }}>
          {renderInline(line)}
        </p>
      );
    }
  });
  flushList('end');
  flushTable('end');

  return <div>{elements}</div>;
}

export default function AdvisorPage() {
  const navigate = useNavigate();
  const bottomRef = useRef(null);
  const fileInputRef = useRef(null);

  const [analyses, setAnalyses] = useState([]);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState('');
  const [status, setStatus] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');

  const [loadingInit, setLoadingInit] = useState(true);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState(null);
  const [failedPrompt, setFailedPrompt] = useState(null);

  // Stage 3: attachment state
  // shape: { file, previewUrl, extractedText, status, filename, message } | null
  const [attachment, setAttachment] = useState(null);
  const [uploadError, setUploadError] = useState(null);
  const [uploading, setUploading] = useState(false);

  const loadStatus = () => {
    api.advisorStatus()
      .then((s) => setStatus(s))
      .catch(() => setStatus({ ollama_connected: false, detail: 'Unable to reach advisor status endpoint.' }));
  };

  useEffect(() => {
    setLoadingInit(true);
    Promise.all([
      api.history().catch(() => []),
      api.advisorStatus().catch(() => ({ ollama_connected: false, detail: 'Status check failed.' })),
    ]).then(([hist, st]) => {
      setAnalyses(Array.isArray(hist) ? hist : []);
      setStatus(st);
    }).finally(() => setLoadingInit(false));
  }, []);

  useEffect(() => {
    setLoadingHistory(true);
    setError(null);
    setFailedPrompt(null);
    api.advisorHistory(selectedAnalysisId || null)
      .then((res) => setMessages(res.messages ?? []))
      .catch((e) => setError(e?.message ?? 'Failed to load conversation history.'))
      .finally(() => setLoadingHistory(false));
  }, [selectedAnalysisId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, sending]);

  const selectedAnalysis = analyses.find((a) => a.id === selectedAnalysisId) || null;

  // ── File Upload Handler ─────────────────────────────────────────────────────
  const handleFileSelect = async (e) => {
    const file = e.target.files?.[0];
    if (!e.target) return;
    // Reset so the same file can be re-selected after removal
    e.target.value = '';
    if (!file) return;

    const ext = '.' + file.name.split('.').pop().toLowerCase();
    const isPdf = ALLOWED_PDF_EXTS.has(ext);
    const isImage = ALLOWED_IMAGE_EXTS.has(ext);
    if (!isPdf && !isImage) {
      setUploadError(`Unsupported file type "${ext}". Allowed: JPG, JPEG, PNG, WEBP, PDF.`);
      return;
    }

    setUploadError(null);
    setAttachment(null);
    setUploading(true);

    const previewUrl = isImage ? URL.createObjectURL(file) : null;
    try {
      const form = new FormData();
      form.append('file', file);
      const result = isPdf
        ? await api.advisorUploadPdf(form)
        : await api.advisorUpload(form);
      setAttachment({
        filename: result.filename || file.name,
        fileType: result.file_type || (isPdf ? 'pdf' : 'image'),
        pageCount: result.page_count || null,
        truncated: Boolean(result.truncated),
        previewUrl,
        extractedText: result.extracted_text || '',
        status: result.status,
        message: result.message || '',
        ok: result.ok,
      });
    } catch (err) {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      setUploadError(err?.message ?? 'File upload failed.');
    } finally {
      setUploading(false);
    }
  };

  const removeAttachment = () => {
    if (attachment?.previewUrl) URL.revokeObjectURL(attachment.previewUrl);
    setAttachment(null);
    setUploadError(null);
  };

  const sendMessage = async (textOverride) => {
    const rawQ = (textOverride ?? input).trim();
    const q = rawQ || (attachment?.ok ? 'Summarize and analyze the IPsec details in this uploaded document.' : '');
    if (!q || sending) return;

    setError(null);
    setFailedPrompt(null);
    if (!textOverride) setInput('');

    // Build attachment_context from successful extraction (ok === true)
    const attachCtx = (attachment?.ok && attachment.extractedText)
      ? {
          filename: attachment.filename,
          file_type: attachment.fileType || 'image',
          extracted_text: attachment.extractedText,
          page_count: attachment.pageCount,
          truncated: attachment.truncated,
        }
      : null;

    const attachLabel = attachment?.fileType === 'pdf' ? 'PDF' : 'Image';
    const optimisticUser = {
      id: `temp-${Date.now()}`,
      role: 'user',
      content: q + (attachCtx ? ` [${attachLabel}: ${attachment.filename}]` : ''),
      references: [],
      created_at: new Date().toISOString(),
    };
    setMessages((prev) => [...prev, optimisticUser]);
    setSending(true);

    // Clear attachment after sending (one-shot context)
    if (attachment?.previewUrl) URL.revokeObjectURL(attachment.previewUrl);
    setAttachment(null);

    try {
      const res = await api.advisorChat(q, selectedAnalysisId || null, attachCtx);
      const assistantMsg = {
        id: res.message_id ?? `asst-${Date.now()}`,
        role: 'assistant',
        content: res.answer,
        references: res.references ?? [],
        model: res.model,
        created_at: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, assistantMsg]);
    } catch (e) {
      setError(e?.message ?? 'Failed to generate response.');
      setFailedPrompt(q);
    } finally {
      setSending(false);
    }
  };

  const handleClear = async () => {
    if (sending) return;
    try {
      await api.advisorClear(selectedAnalysisId || null);
      setMessages([]);
      setError(null);
      setFailedPrompt(null);
    } catch (e) {
      setError(e?.message ?? 'Failed to clear conversation.');
    }
  };

  const isGroq = status?.backend === 'groq';
  const modelReady = isGroq
    ? Boolean(status?.chat_model_available && status?.embed_model_available)
    : Boolean(status?.ollama_connected && status?.chat_model_available && status?.embed_model_available);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxWidth: 960, margin: '0 auto' }}>

      {/* ── Header ────────────────────────────────────────── */}
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '1rem 1.25rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.875rem',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{
            width: 36, height: 36, borderRadius: 9,
            backgroundColor: 'var(--blue-light)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '1px solid var(--blue-border)', flexShrink: 0,
          }}>
            <Sparkles size={18} style={{ color: 'var(--blue)' }} />
          </div>
          <div style={{ flex: 1, minWidth: 200 }}>
            <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
              IPsec Security Assistant
            </h1>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
              RAG-powered security chatbot grounded in your PCAP findings, timeline events, beaconing telemetry, and ML explainability.
            </p>
          </div>

          {/* Model Connection Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '4px 10px', borderRadius: 9999, fontSize: 11, fontWeight: 600,
              backgroundColor: modelReady ? 'var(--green-light)' : 'var(--red-light)',
              color: modelReady ? 'var(--green-text)' : 'var(--red-text)',
              border: `1px solid ${modelReady ? 'var(--green-border)' : 'var(--red-border)'}`,
            }}>
              {modelReady ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
              {status === null
                ? 'Checking model…'
                : modelReady
                  ? isGroq
                    ? `Groq Connected (${status.chat_model})`
                    : `Ollama Connected (${status.chat_model})`
                  : status.detail || 'Model Disconnected'}
            </div>
            <button
              type="button"
              onClick={loadStatus}
              title="Refresh model status"
              style={{
                padding: '5px', borderRadius: 6,
                border: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)',
                color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center',
              }}
            >
              <RefreshCw size={12} />
            </button>
          </div>
        </div>

        {/* ── Analysis Selector & Clear Controls ────────────── */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
          paddingTop: '0.75rem', borderTop: '1px solid var(--border)',
        }}>
          <label htmlFor="advisor-analysis-select" style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>
            Context Scope:
          </label>
          <select
            id="advisor-analysis-select"
            value={selectedAnalysisId}
            onChange={(e) => setSelectedAnalysisId(e.target.value)}
            disabled={loadingInit || sending}
            style={{
              flex: '1 1 260px',
              padding: '0.42rem 0.75rem',
              borderRadius: 7,
              border: '1px solid var(--border)',
              backgroundColor: 'var(--bg-surface)',
              color: 'var(--text-primary)',
              fontSize: 12,
            }}
          >
            <option value="">All My Analyses ({analyses.length})</option>
            {analyses.map((a) => (
              <option key={a.id} value={a.id}>
                {a.filename} — {a.id.slice(0, 8)} ({a.risk_level || 'Unknown'})
              </option>
            ))}
          </select>

          {selectedAnalysis && (
            <button
              type="button"
              onClick={() => navigate(`/analysis/${selectedAnalysis.id}`)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '0.4rem 0.7rem', borderRadius: 7,
                border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
                color: 'var(--blue)', fontSize: 11, fontWeight: 600, cursor: 'pointer',
              }}
            >
              <FileText size={12} /> {selectedAnalysis.filename} ({selectedAnalysis.id.slice(0, 8)}) <ArrowRight size={11} />
            </button>
          )}

          <button
            type="button"
            onClick={handleClear}
            disabled={sending || messages.length === 0}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              padding: '0.4rem 0.7rem', borderRadius: 7,
              border: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)',
              color: messages.length === 0 ? 'var(--text-faint)' : 'var(--text-secondary)',
              fontSize: 11, fontWeight: 600,
              cursor: messages.length === 0 ? 'not-allowed' : 'pointer',
              marginLeft: 'auto',
            }}
          >
            <Trash2 size={12} /> Clear Chat
          </button>
        </div>
      </div>

      {/* ── Suggested Questions ───────────────────────────── */}
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '0.75rem 1rem',
      }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 6 }}>
          Suggested Questions
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {SUGGESTED_QUESTIONS.map((q) => (
            <button
              key={q}
              type="button"
              disabled={sending}
              onClick={() => sendMessage(q)}
              style={{
                padding: '0.32rem 0.65rem',
                borderRadius: 9999,
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-surface)',
                color: 'var(--text-secondary)',
                fontSize: 11,
                fontWeight: 500,
                cursor: sending ? 'not-allowed' : 'pointer',
              }}
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* ── Chat Transcript ───────────────────────────────── */}
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 10,
        padding: '1rem 1.25rem',
        minHeight: 340,
        maxHeight: '55vh',
        overflowY: 'auto',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.875rem',
      }}>
        {loadingHistory ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', gap: 8, color: 'var(--text-muted)', fontSize: 12 }}>
            <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> Loading conversation…
          </div>
        ) : messages.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            textAlign: 'center', padding: '2.5rem 1rem', gap: 8,
          }}>
            <MessageSquare size={28} style={{ color: 'var(--text-muted)', opacity: 0.6 }} />
            <p style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
              Ask about your IPsec PCAP analyses
            </p>
            <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)', maxWidth: 420 }}>
              {analyses.length === 0
                ? 'Upload a PCAP file first, or ask a general IPsec question below.'
                : `Retrieving evidence from ${selectedAnalysis ? `${selectedAnalysis.filename} (${selectedAnalysis.id.slice(0, 8)})` : `all ${analyses.length} of your analyses`}.`}
            </p>
          </div>
        ) : (
          messages.map((m) => (
            <ChatBubble key={m.id} message={m} navigate={navigate} />
          ))
        )}

        {sending && (
          <div style={{
            alignSelf: 'flex-start',
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '0.65rem 0.9rem',
            borderRadius: 10,
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            fontSize: 12,
            color: 'var(--text-muted)',
          }}>
            <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
            Retrieving PCAP evidence and generating response…
          </div>
        )}

        {error && (
          <div style={{
            padding: '0.75rem 0.9rem',
            borderRadius: 8,
            backgroundColor: 'var(--red-light)',
            border: '1px solid var(--red-border)',
            color: 'var(--red-text)',
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}>
            <AlertTriangle size={14} style={{ flexShrink: 0 }} />
            <span style={{ flex: 1 }}>{error}</span>
            {failedPrompt && (
              <button
                type="button"
                onClick={() => sendMessage(failedPrompt)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  padding: '0.25rem 0.6rem', borderRadius: 6,
                  border: '1px solid var(--red-border)', backgroundColor: 'var(--bg-card)',
                  color: 'var(--red-text)', fontSize: 11, fontWeight: 600, cursor: 'pointer',
                }}
              >
                <RotateCcw size={11} /> Retry
              </button>
            )}
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* ── Input Form ────────────────────────────────────── */}
      <form
        onSubmit={(e) => { e.preventDefault(); sendMessage(); }}
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
          backgroundColor: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          padding: '0.625rem 0.75rem',
        }}
      >
        {/* Hidden file input */}
        <input
          ref={fileInputRef}
          type="file"
          accept=".jpg,.jpeg,.png,.webp,.pdf"
          style={{ display: 'none' }}
          onChange={handleFileSelect}
        />

        {/* Upload error */}
        {uploadError && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6, fontSize: 11,
            padding: '4px 8px', borderRadius: 6,
            backgroundColor: 'var(--red-light)', border: '1px solid var(--red-border)',
            color: 'var(--red-text)',
          }}>
            <AlertTriangle size={12} />
            <span style={{ flex: 1 }}>{uploadError}</span>
            <button type="button" onClick={() => setUploadError(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--red-text)' }}>
              <XIcon size={12} />
            </button>
          </div>
        )}

        {/* Uploading spinner */}
        {uploading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--text-muted)' }}>
            <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} />
            Uploading and extracting text…
          </div>
        )}

        {/* Attachment preview chip */}
        {attachment && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap',
            padding: '5px 10px', borderRadius: 7,
            border: `1px solid ${attachment.ok ? 'var(--green-border)' : attachment.status === 'ocr_unavailable' ? 'var(--yellow-border)' : 'var(--border)'}`,
            backgroundColor: attachment.ok ? 'var(--green-light)' : attachment.status === 'ocr_unavailable' ? 'var(--yellow-light)' : 'var(--bg-surface)',
            fontSize: 11,
          }}>
            {attachment.fileType === 'pdf'
              ? <FileText size={12} style={{ flexShrink: 0 }} />
              : <ImageIcon size={12} style={{ flexShrink: 0 }} />}
            <span style={{ fontWeight: 600 }}>{attachment.filename}</span>
            {attachment.ok && (
              <span style={{ color: 'var(--green-text)' }}>
                ✓ {attachment.extractedText.length} chars extracted
                {attachment.pageCount ? ` (${attachment.pageCount}p)` : ''}
                {attachment.truncated ? ' — truncated' : ''}
              </span>
            )}
            {attachment.status === 'ocr_unavailable' && (
              <span style={{ color: 'var(--yellow-text)' }}>⚠ Tesseract not installed — text extraction unavailable</span>
            )}
            {attachment.status === 'page_limit_exceeded' && (
              <span style={{ color: 'var(--red-text)' }}>⚠ {attachment.message || 'PDF exceeds 50-page limit'}</span>
            )}
            {(attachment.status === 'encrypted' || attachment.status === 'empty') && (
              <span style={{ color: 'var(--red-text)' }}>⚠ {attachment.message}</span>
            )}
            {attachment.status === 'no_text_found' && (
              <span style={{ color: 'var(--text-muted)' }}>No readable text detected</span>
            )}
            {attachment.status === 'unreadable' && (
              <span style={{ color: 'var(--text-muted)' }}>Could not extract text — try a clearer file</span>
            )}
            <button
              type="button"
              onClick={removeAttachment}
              title="Remove attachment"
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', marginLeft: 'auto', display: 'flex', alignItems: 'center' }}
            >
              <XIcon size={12} />
            </button>
          </div>
        )}

        {/* Text input row */}
        <div style={{ display: 'flex', gap: 8 }}>
          {/* Paperclip / attach button */}
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            disabled={sending || uploading}
            title="Attach image or PDF (JPG, JPEG, PNG, WEBP, PDF)"
            style={{
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              width: 36, height: 36, flexShrink: 0,
              borderRadius: 7, border: '1px solid var(--border)',
              backgroundColor: attachment ? 'var(--blue-light)' : 'var(--bg-surface)',
              color: attachment ? 'var(--blue)' : 'var(--text-muted)',
              cursor: (sending || uploading) ? 'not-allowed' : 'pointer',
              opacity: (sending || uploading) ? 0.5 : 1,
            }}
          >
            <Paperclip size={15} />
          </button>

          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about findings, encryption, DH group, risk score, skipped rules, or packets…"
            disabled={sending}
            style={{
              flex: 1,
              border: '1px solid var(--border)',
              borderRadius: 7,
              padding: '0.5rem 0.75rem',
              backgroundColor: 'var(--bg-surface)',
              color: 'var(--text-primary)',
              fontSize: 13,
            }}
          />
          <button
            type="submit"
            disabled={sending || (!input.trim() && !attachment)}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '0.5rem 1rem',
              borderRadius: 7,
              border: '1px solid var(--blue-border)',
              backgroundColor: 'var(--blue-light)',
              color: 'var(--blue)',
              fontSize: 13,
              fontWeight: 600,
              cursor: (sending || (!input.trim() && !attachment)) ? 'not-allowed' : 'pointer',
              opacity: (sending || (!input.trim() && !attachment)) ? 0.6 : 1,
            }}
          >
            {sending ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Send size={14} />}
            Send
          </button>
        </div>
      </form>
    </div>
  );
}

function ChatBubble({ message: m, navigate }) {
  const isUser = m.role === 'user';
  const refs = m.references || [];

  return (
    <div style={{
      alignSelf: isUser ? 'flex-end' : 'flex-start',
      maxWidth: isUser ? '78%' : '92%',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
      padding: '0.75rem 1rem',
      borderRadius: 10,
      backgroundColor: isUser ? 'var(--blue-light)' : 'var(--bg-surface)',
      border: `1px solid ${isUser ? 'var(--blue-border)' : 'var(--border)'}`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: 'var(--text-muted)' }}>
        <strong style={{ color: isUser ? 'var(--blue)' : 'var(--text-secondary)' }}>
          {isUser ? 'You' : 'IPsec Security Assistant'}
        </strong>
        {m.model && <span>({m.model})</span>}
        {m.created_at && <span style={{ marginLeft: 'auto' }}>{fmtDate(m.created_at)}</span>}
      </div>

      {isUser ? (
        <p style={{ margin: 0, fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.5 }}>{m.content}</p>
      ) : (
        <MarkdownBlock content={m.content} />
      )}

      {/* Evidence References */}
      {!isUser && refs.length > 0 && (
        <div style={{
          marginTop: 4,
          paddingTop: 6,
          borderTop: '1px solid var(--border)',
          display: 'flex',
          flexDirection: 'column',
          gap: 5,
        }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Evidence References
          </div>
          {refs.map((r) => (
            <div key={r.analysis_id} style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', fontSize: 11 }}>
              <button
                type="button"
                onClick={() => navigate(`/analysis/${r.analysis_id}`)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  padding: '2px 7px', borderRadius: 5,
                  border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
                  color: 'var(--blue)', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
                }}
              >
                <FileText size={10} /> {r.filename} ({r.analysis_id.slice(0, 8)}) <ArrowRight size={9} />
              </button>

              {(r.finding_ids || []).map((fid) => (
                <button
                  key={fid}
                  type="button"
                  onClick={() => navigate('/findings')}
                  title={`Open Findings page (${fid})`}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 3,
                    padding: '2px 6px', borderRadius: 5,
                    border: '1px solid var(--yellow-border)', backgroundColor: 'var(--yellow-light)',
                    color: 'var(--yellow-text)', fontSize: 10, fontFamily: 'monospace', fontWeight: 700, cursor: 'pointer',
                  }}
                >
                  <Shield size={9} /> {fid}
                </button>
              ))}

              {(r.packet_numbers || []).length > 0 && (
                <span style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                  Packets: #{r.packet_numbers.slice(0, 8).join(', #')}
                  {r.packet_numbers.length > 8 ? '…' : ''}
                </span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
