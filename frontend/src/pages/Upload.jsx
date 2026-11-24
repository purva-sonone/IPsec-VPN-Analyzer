import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud, File, AlertCircle, CheckCircle2,
  Loader2, Shield, Cpu, ListChecks, X, FolderOpen, ArrowRight
} from 'lucide-react';
import { api } from '../lib/api';

const STEPS = [
  'Upload received & verified',
  'Parsing packet headers (PyShark / TShark)',
  'Extracting IKEv1/IKEv2 & ESP parameters',
  'Evaluating security rules & cryptographic margin',
  'Computing behavioral timing & jitter metrics',
  'Running Random Forest ML classification & XAI',
  'Finalizing audit telemetry report',
];

export default function Upload() {
  const navigate  = useNavigate();
  const inputRef  = useRef(null);
  const [file,      setFile]      = useState(null);
  const [dragging,  setDragging]  = useState(false);
  const [uploading, setUploading] = useState(false);
  const [step,      setStep]      = useState(-1);
  const [error,     setError]     = useState(null);

  const selectFile = (f) => {
    if (!f) return;
    const ok = f.name.endsWith('.pcap') || f.name.endsWith('.pcapng') || f.name.endsWith('.cap');
    if (!ok) {
      setError('Unsupported file type. Please upload a valid .pcap, .pcapng, or .cap capture file.');
      return;
    }
    setFile(f);
    setError(null);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      selectFile(e.dataTransfer.files[0]);
    }
  };

  const advanceStep = (n) => new Promise(res => setTimeout(() => { setStep(n); res(); }, 320));

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true);
    setError(null);
    for (let i = 0; i < STEPS.length - 1; i++) {
      await advanceStep(i);
    }
    const form = new FormData();
    form.append('file', file);
    try {
      const data = await api.upload(form);
      await advanceStep(STEPS.length - 1);
      setTimeout(() => navigate(`/analysis/${data.id}`, { state: { result: data } }), 400);
    } catch (e) {
      setError(e.message || 'Upload analysis failed. Please verify the backend service is running.');
      setUploading(false);
      setStep(-1);
    }
  };

  return (
    <div style={{ maxWidth: 720, margin: '0 auto' }} className="page-content">

      {/* ── Page header ──────────────────────────────────────────────── */}
      <div>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em' }}>
          Analyze PCAP Capture
        </h1>
        <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4, marginBottom: 0 }}>
          Upload a packet capture file to run automated IPsec VPN protocol analysis, rule compliance auditing, and XAI traffic classification.
        </p>
      </div>

      {/* ── Drop zone ────────────────────────────────────────────────── */}
      {!uploading && (
        <div
          className={`drop-zone${dragging ? ' dragging' : ''}`}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          style={{
            padding: '3rem 2rem',
            textAlign: 'center',
            cursor: file ? 'default' : 'pointer',
            backgroundColor: 'var(--bg-card)',
            borderColor: dragging ? 'var(--blue)' : 'var(--border)',
            boxShadow: 'var(--shadow-card)',
          }}
          onClick={() => !file && inputRef.current?.click()}
        >
          <input
            ref={inputRef}
            type="file"
            style={{ display: 'none' }}
            accept=".pcap,.pcapng,.cap"
            onChange={e => selectFile(e.target.files[0])}
          />

          {!file ? (
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <div style={{
                display: 'inline-flex',
                padding: '1.125rem',
                borderRadius: 16,
                backgroundColor: 'var(--blue-light)',
                border: '1px solid var(--blue-border)',
                marginBottom: '1.25rem',
              }}>
                <UploadCloud style={{ width: 36, height: 36, color: 'var(--blue)' }} />
              </div>
              <p style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
                Drag and drop your PCAP file here
              </p>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
                or click anywhere in this box to select a file
              </p>

              <button
                type="button"
                onClick={(e) => { e.stopPropagation(); inputRef.current?.click(); }}
                className="btn-secondary"
                style={{ fontSize: 13, padding: '0.45rem 1rem' }}
              >
                <FolderOpen size={15} /> Browse Files
              </button>

              <div style={{ display: 'flex', gap: 6, marginTop: '1.5rem', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Supported:</span>
                <span className="badge badge-neutral">.pcap</span>
                <span className="badge badge-neutral">.pcapng</span>
                <span className="badge badge-neutral">.cap</span>
              </div>
            </div>
          ) : (
            <div style={{ width: '100%', maxWidth: 500, margin: '0 auto' }}>
              {/* Selected file preview */}
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '1rem 1.25rem',
                backgroundColor: 'var(--bg-surface)',
                borderRadius: 10,
                border: '1px solid var(--border)',
                marginBottom: '1.25rem',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.875rem' }}>
                  <div style={{
                    padding: '0.625rem',
                    backgroundColor: 'var(--blue-light)',
                    borderRadius: 8,
                    border: '1px solid var(--blue-border)',
                  }}>
                    <File style={{ width: 20, height: 20, color: 'var(--blue)' }} />
                  </div>
                  <div style={{ textAlign: 'left' }}>
                    <p style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                      {file.name}
                    </p>
                    <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: '3px 0 0' }}>
                      {(file.size / 1024).toFixed(1)} KB · Ready for analysis
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); setFile(null); setError(null); }}
                  style={{
                    padding: '0.4rem',
                    borderRadius: 6,
                    backgroundColor: 'transparent',
                    border: '1px solid var(--border)',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    display: 'flex',
                  }}
                  title="Remove selected file"
                >
                  <X style={{ width: 15, height: 15 }} />
                </button>
              </div>

              <button
                type="button"
                onClick={handleUpload}
                disabled={uploading}
                className="btn-primary"
                style={{
                  width: '100%',
                  justifyContent: 'center',
                  padding: '0.75rem',
                  fontSize: 14,
                  fontWeight: 600,
                  borderRadius: 10,
                }}
              >
                <UploadCloud style={{ width: 17, height: 17 }} /> Start Analysis Engine
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Analysis progress state ───────────────────────────────────── */}
      {uploading && (
        <div className="card" style={{ padding: '2.5rem 2rem' }}>
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <div style={{
              display: 'inline-flex',
              padding: '1rem',
              borderRadius: 16,
              backgroundColor: 'var(--blue-light)',
              border: '1px solid var(--blue-border)',
              marginBottom: '1rem',
            }}>
              <Loader2 style={{ width: 32, height: 32, color: 'var(--blue)', animation: 'spin 1s linear infinite' }} />
            </div>
            <h2 style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Analyzing Capture File…
            </h2>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4 }}>
              Dissecting packet frames, evaluating cryptographic parameters, and computing telemetry.
            </p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {STEPS.map((s, i) => {
              const done    = i < step;
              const current = i === step;
              const pending = i > step;
              return (
                <div
                  key={s}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 12,
                    padding: '0.75rem 1rem',
                    borderRadius: 8,
                    backgroundColor: current
                      ? 'var(--blue-light)'
                      : done
                        ? 'var(--green-light)'
                        : 'var(--bg-surface)',
                    border: `1px solid ${
                      current
                        ? 'var(--blue-border)'
                        : done
                          ? 'var(--green-border)'
                          : 'var(--border)'
                    }`,
                    transition: 'all 250ms ease',
                  }}
                >
                  {done && <CheckCircle2 style={{ width: 16, height: 16, color: 'var(--green)', flexShrink: 0 }} />}
                  {current && <Loader2 style={{ width: 16, height: 16, color: 'var(--blue)', animation: 'spin 1s linear infinite', flexShrink: 0 }} />}
                  {pending && (
                    <div style={{
                      width: 16,
                      height: 16,
                      borderRadius: '50%',
                      border: '2px solid var(--text-faint)',
                      flexShrink: 0,
                    }} />
                  )}
                  <span style={{
                    fontSize: 13,
                    fontWeight: current ? 600 : 500,
                    color: done
                      ? 'var(--green-text)'
                      : current
                        ? 'var(--blue-text)'
                        : 'var(--text-muted)',
                  }}>
                    {s}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Error Banner ──────────────────────────────────────────────── */}
      {error && (
        <div className="alert-error" style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <AlertCircle style={{ width: 16, height: 16, color: 'var(--red)', flexShrink: 0, marginTop: 1 }} />
          <p style={{ fontSize: 13, color: 'var(--red)', margin: 0 }}>{error}</p>
        </div>
      )}

      {/* ── Feature Cards ─────────────────────────────────────────────── */}
      {!uploading && !file && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginTop: '0.5rem' }}>
          {[
            {
              icon: Shield,
              title: 'Protocol & Crypto Audit',
              desc: 'Extracts IKEv1/IKEv2 phases, encryption algorithms, DH group strength, and ESP/AH payload enforcement.'
            },
            {
              icon: ListChecks,
              title: 'Rule Compliance Engine',
              desc: 'Validates capture telemetry against NIST guidelines with distinct PASS, FAIL, REVIEW, and NOT OBSERVED audit.'
            },
            {
              icon: Cpu,
              title: 'Explainable AI Classification',
              desc: 'Classifies traffic categories (C2, VOIP, Streaming) and breaks down top tree decision path features.'
            },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="card" style={{ padding: '1.25rem' }}>
              <div style={{
                width: 36,
                height: 36,
                borderRadius: 8,
                backgroundColor: 'var(--blue-light)',
                border: '1px solid var(--blue-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: '0.875rem',
              }}>
                <Icon style={{ width: 18, height: 18, color: 'var(--blue)' }} />
              </div>
              <p style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
                {title}
              </p>
              <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55, margin: 0 }}>
                {desc}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
