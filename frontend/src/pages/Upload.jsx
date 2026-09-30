import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud, File, AlertCircle, CheckCircle2,
  Loader2, Shield, Cpu, ListChecks, X,
} from 'lucide-react';
import { api } from '../lib/api';

const STEPS = [
  'Upload received',
  'Reading packets',
  'Extracting IKE/IPsec parameters',
  'Evaluating security rules',
  'Running ML classification',
  'Generating results',
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
    if (!ok) { setError('Only .pcap, .pcapng, and .cap files are supported.'); return; }
    setFile(f); setError(null);
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragging(false);
    selectFile(e.dataTransfer.files[0]);
  };

  const advanceStep = (n) => new Promise(res => setTimeout(() => { setStep(n); res(); }, 350));

  const handleUpload = async () => {
    if (!file) return;
    setUploading(true); setError(null);
    for (let i = 0; i < STEPS.length - 1; i++) await advanceStep(i);
    const form = new FormData();
    form.append('file', file);
    try {
      const data = await api.upload(form);
      await advanceStep(STEPS.length - 1);
      setTimeout(() => navigate(`/analysis/${data.id}`, { state: { result: data } }), 400);
    } catch (e) {
      setError(e.message || 'Upload failed. Check backend.');
      setUploading(false); setStep(-1);
    }
  };

  return (
    <div style={{ maxWidth: 640, margin: '0 auto' }} className="page-content">

      {/* ── Page header ──────────────────────────────────────────────── */}
      <div>
        <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#0F172A', margin: 0 }}>
          Analyze PCAP
        </h1>
        <p style={{ fontSize: 13, color: '#64748B', marginTop: 4 }}>
          Upload a packet capture file to run full IPsec security analysis and ML traffic classification.
        </p>
      </div>

      {/* ── Drop zone ────────────────────────────────────────────────── */}
      {!uploading && (
        <div
          className={`drop-zone${dragging ? ' dragging' : ''}`}
          onDragOver={e => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => !file && inputRef.current?.click()}
          style={{ padding: '2.5rem 2rem', textAlign: 'center', cursor: file ? 'default' : 'pointer' }}>

          <input ref={inputRef} type="file" style={{ display: 'none' }}
            accept=".pcap,.pcapng,.cap" onChange={e => selectFile(e.target.files[0])} />

          {!file ? (
            <>
              <div style={{ display: 'inline-flex', padding: '1rem', borderRadius: 14, backgroundColor: '#EFF6FF', marginBottom: '1rem' }}>
                <UploadCloud style={{ width: 32, height: 32, color: '#2563EB' }} />
              </div>
              <p style={{ fontSize: 15, fontWeight: 600, color: '#0F172A', marginBottom: 6 }}>
                Click to browse or drag & drop
              </p>
              <p style={{ fontSize: 12, color: '#94A3B8' }}>
                Supported formats: <strong>.pcap</strong>, <strong>.pcapng</strong>, <strong>.cap</strong>
              </p>
            </>
          ) : (
            <div style={{ width: '100%' }}>
              {/* Selected file */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.875rem 1rem', backgroundColor: '#F8FAFC', borderRadius: 10, border: '1px solid #E2E8F0', marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ padding: '0.5rem', backgroundColor: '#EFF6FF', borderRadius: 8 }}>
                    <File style={{ width: 16, height: 16, color: '#2563EB' }} />
                  </div>
                  <div style={{ textAlign: 'left' }}>
                    <p style={{ fontSize: 13, fontWeight: 600, color: '#0F172A', marginBottom: 2 }}>{file.name}</p>
                    <p style={{ fontSize: 11, color: '#94A3B8' }}>{(file.size / 1024).toFixed(1)} KB</p>
                  </div>
                </div>
                <button
                  onClick={e => { e.stopPropagation(); setFile(null); setError(null); }}
                  style={{ padding: '0.375rem', borderRadius: 6, backgroundColor: 'transparent', border: '1px solid #E2E8F0', color: '#94A3B8', cursor: 'pointer', display: 'flex' }}>
                  <X style={{ width: 14, height: 14 }} />
                </button>
              </div>
              <button onClick={handleUpload} disabled={uploading}
                className="btn-primary"
                style={{ width: '100%', justifyContent: 'center', padding: '0.75rem', fontSize: 14, fontWeight: 600, borderRadius: 10 }}>
                <UploadCloud style={{ width: 16, height: 16 }} /> Upload & Analyze
              </button>
            </div>
          )}
        </div>
      )}

      {/* ── Analysis progress ─────────────────────────────────────────── */}
      {uploading && (
        <div className="card" style={{ padding: '2rem' }}>
          <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
            <div style={{ display: 'inline-flex', padding: '1rem', borderRadius: 12, backgroundColor: '#EFF6FF', marginBottom: '0.875rem' }}>
              <Loader2 style={{ width: 28, height: 28, color: '#2563EB', animation: 'spin 1s linear infinite' }} />
            </div>
            <h2 style={{ fontSize: 16, fontWeight: 600, color: '#0F172A', marginBottom: 4 }}>Analyzing PCAP…</h2>
            <p style={{ fontSize: 13, color: '#64748B' }}>Please wait while we inspect your capture file.</p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {STEPS.map((s, i) => {
              const done    = i < step;
              const current = i === step;
              const pending = i > step;
              return (
                <div key={s} style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '0.625rem 0.875rem',
                  borderRadius: 8,
                  backgroundColor: current ? '#EFF6FF' : done ? '#F0FDF4' : '#F8FAFC',
                  border: `1px solid ${current ? '#BFDBFE' : done ? '#BBF7D0' : '#E2E8F0'}`,
                  transition: 'all 300ms',
                }}>
                  {done    && <CheckCircle2 style={{ width: 16, height: 16, color: '#16A34A', flexShrink: 0 }} />}
                  {current && <Loader2 style={{ width: 16, height: 16, color: '#2563EB', animation: 'spin 1s linear infinite', flexShrink: 0 }} />}
                  {pending && <div style={{ width: 16, height: 16, borderRadius: '50%', border: '2px solid #CBD5E1', flexShrink: 0 }} />}
                  <span style={{ fontSize: 13, fontWeight: 500, color: done ? '#16A34A' : current ? '#2563EB' : '#94A3B8' }}>
                    {s}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Error ─────────────────────────────────────────────────────── */}
      {error && (
        <div className="alert-error">
          <AlertCircle style={{ width: 15, height: 15, color: '#B91C1C', flexShrink: 0, marginTop: 1 }} />
          <p style={{ fontSize: 13, color: '#B91C1C' }}>{error}</p>
        </div>
      )}

      {/* ── Feature cards ─────────────────────────────────────────────── */}
      {!uploading && !file && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.875rem' }}>
          {[
            { icon: Shield,     title: 'Security Analysis',  desc: 'IKE, ESP, encryption, DH group and authentication evaluation' },
            { icon: ListChecks, title: 'Rule Audit',         desc: 'Security rule engine with PASS/FAIL/SKIPPED per finding' },
            { icon: Cpu,        title: 'ML Classification',  desc: 'Traffic category classification using trained RandomForest model' },
          ].map(({ icon: Icon, title, desc }) => (
            <div key={title} className="card" style={{ padding: '1.125rem' }}>
              <div style={{ width: 36, height: 36, borderRadius: 8, backgroundColor: '#EFF6FF', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '0.75rem' }}>
                <Icon style={{ width: 16, height: 16, color: '#2563EB' }} />
              </div>
              <p style={{ fontSize: 13, fontWeight: 600, color: '#0F172A', marginBottom: 4 }}>{title}</p>
              <p style={{ fontSize: 11, color: '#64748B', lineHeight: 1.6 }}>{desc}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
