import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, AlertTriangle, Search, Filter,
  ArrowRight, Loader2, Info, FileText, ChevronDown,
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate, sevColor } from '../lib/utils';

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────
const SEVERITIES = ['All', 'Critical', 'High', 'Medium', 'Low', 'Informational'];
const STATUSES   = ['All', 'Action Required', 'Informational'];
const SORTS      = ['Severity (High First)', 'Newest First', 'Oldest First'];
const SEV_RANK   = { Critical: 0, High: 1, Medium: 2, Low: 3, Informational: 4 };

function statusColor(status) {
  if (status === 'Action Required') return 'badge-high';
  return 'badge-info';
}

function obsStyle(type) {
  if (type === 'Observed')
    return { background: 'var(--blue-light)', color: 'var(--blue)', border: '1px solid var(--blue-border)' };
  return { background: 'var(--yellow-light)', color: 'var(--yellow-text)', border: '1px solid var(--yellow-border)' };
}

// ─────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────
export default function FindingsPage() {
  const navigate = useNavigate();

  const [findings,  setFindings]  = useState([]);
  const [loading,   setLoading]   = useState(true);
  const [error,     setError]     = useState(null);
  const [expanded,  setExpanded]  = useState(null); // finding_id of expanded card

  // Filters
  const [query,    setQuery]    = useState('');
  const [severity, setSeverity] = useState('All');
  const [status,   setStatus]   = useState('All');
  const [sort,     setSort]     = useState('Severity (High First)');

  useEffect(() => {
    setLoading(true);
    api.findings()
      .then((data) => {
        setFindings(data.findings ?? []);
      })
      .catch((e) => setError(e?.message ?? 'Failed to load findings.'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() => {
    let list = [...findings];

    // Search
    if (query.trim()) {
      const q = query.trim().toLowerCase();
      list = list.filter(
        (f) =>
          f.finding_id?.toLowerCase().includes(q) ||
          f.title?.toLowerCase().includes(q) ||
          f.affected_parameter?.toLowerCase().includes(q),
      );
    }

    // Severity
    if (severity !== 'All') list = list.filter((f) => f.severity === severity);

    // Status
    if (status !== 'All') list = list.filter((f) => f.status === status);

    // Sort
    list.sort((a, b) => {
      const ta = new Date(a.created_at ?? 0).getTime();
      const tb = new Date(b.created_at ?? 0).getTime();
      if (sort === 'Severity (High First)') {
        const ra = SEV_RANK[a.severity] ?? 99;
        const rb = SEV_RANK[b.severity] ?? 99;
        if (ra !== rb) return ra - rb;
        return tb - ta;
      }
      return sort === 'Newest First' ? tb - ta : ta - tb;
    });

    return list;
  }, [findings, query, severity, status, sort]);

  // ── Render ────────────────────────────────────────────────
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: 900, margin: '0 auto' }}>

      {/* ── Page Header ───────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 9,
          backgroundColor: 'var(--blue-light)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid var(--blue-border)', flexShrink: 0,
        }}>
          <Shield size={18} style={{ color: 'var(--blue)' }} />
        </div>
        <div>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
            Security Findings
          </h1>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
            Evidence-based cryptographic and protocol rule findings from your PCAP analyses.
          </p>
        </div>
        <div style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>
          {loading ? '…' : `${filtered.length} of ${findings.length} findings`}
        </div>
      </div>

      {/* ── Filter Bar ────────────────────────────────────── */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: '0.625rem',
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border)', borderRadius: 10,
        padding: '0.75rem 1rem',
      }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: '1 1 180px', minWidth: 160 }}>
          <Search size={13} style={{
            position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)',
            color: 'var(--text-muted)', pointerEvents: 'none',
          }} />
          <input
            type="text"
            placeholder="Search by ID or title…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              width: '100%', padding: '0.4rem 0.5rem 0.4rem 2rem',
              border: '1px solid var(--border)', borderRadius: 7,
              backgroundColor: 'var(--bg-surface)', color: 'var(--text-primary)',
              fontSize: 12, boxSizing: 'border-box',
            }}
          />
        </div>

        {/* Severity */}
        <FilterSelect label="Severity" value={severity} options={SEVERITIES} onChange={setSeverity} />

        {/* Status */}
        <FilterSelect label="Status" value={status} options={STATUSES} onChange={setStatus} />

        {/* Sort */}
        <FilterSelect label="Sort" value={sort} options={SORTS} onChange={setSort} />
      </div>

      {/* ── Content ───────────────────────────────────────── */}
      {loading ? (
        <LoadingState />
      ) : error ? (
        <ErrorState message={error} />
      ) : findings.length === 0 ? (
        <EmptyState
          icon={<Shield size={32} style={{ color: 'var(--text-muted)', opacity: 0.6 }} />}
          title="No findings yet"
          body="Upload a PCAP file to run security rule evaluations and generate findings."
          action={{ label: 'Analyze PCAP', onClick: () => navigate('/upload') }}
        />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Filter size={32} style={{ color: 'var(--text-muted)', opacity: 0.6 }} />}
          title="No matches"
          body="Try adjusting your search query or filter options."
        />
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
          {filtered.map((f) => (
            <FindingCard
              key={f.finding_id}
              finding={f}
              expanded={expanded === f.finding_id}
              onToggle={() => setExpanded(expanded === f.finding_id ? null : f.finding_id)}
              onNavigate={() => navigate(`/analysis/${f.analysis_id}`)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// FindingCard
// ─────────────────────────────────────────────────────────────
function FindingCard({ finding: f, expanded, onToggle, onNavigate }) {
  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      overflow: 'hidden',
    }}>
      {/* Header row — always visible */}
      <div
        role="button"
        tabIndex={0}
        onClick={onToggle}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onToggle(); }}
        style={{
          display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
          padding: '0.75rem 1rem', cursor: 'pointer',
          backgroundColor: expanded ? 'var(--bg-surface)' : 'transparent',
          borderBottom: expanded ? '1px solid var(--border)' : 'none',
        }}
      >
        {/* Severity icon dot */}
        <span style={{
          width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
          backgroundColor:
            f.severity === 'High' || f.severity === 'Critical' ? 'var(--red)' :
            f.severity === 'Medium' ? 'var(--yellow)' :
            f.severity === 'Low' ? 'var(--blue)' : 'var(--green)',
        }} />

        {/* Finding ID */}
        <span style={{
          fontFamily: 'monospace', fontSize: 10, fontWeight: 700,
          color: 'var(--text-muted)', flexShrink: 0,
        }}>
          {f.finding_id}
        </span>

        {/* Title */}
        <span style={{
          fontSize: 13, fontWeight: 700, color: 'var(--text-primary)',
          flex: 1, minWidth: 0,
        }}>
          {f.title}
        </span>

        {/* Badges */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, flexShrink: 0 }}>
          <span className={`badge ${sevColor(f.severity)}`} style={{ fontSize: 10 }}>
            {f.severity}
          </span>
          <span className={`badge ${statusColor(f.status)}`} style={{ fontSize: 10 }}>
            {f.status}
          </span>
          {f.observation_type && (
            <span style={{
              fontSize: 10, fontWeight: 600, padding: '2px 7px',
              borderRadius: 9999, ...obsStyle(f.observation_type),
            }}>
              {f.observation_type}
            </span>
          )}
        </div>

        {/* Meta */}
        <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
          {fmtDate(f.created_at)}
        </span>

        <ChevronDown size={14} style={{
          color: 'var(--text-muted)', flexShrink: 0,
          transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)',
          transition: 'transform 0.2s',
        }} />
      </div>

      {/* Expanded detail */}
      {expanded && (
        <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>

          {/* Affected parameter */}
          <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            <strong style={{ color: 'var(--text-secondary)' }}>Affected Parameter:</strong>{' '}
            {f.affected_parameter || '—'}
            {f.filename && (
              <span style={{ marginLeft: 12, fontFamily: 'monospace', fontSize: 10 }}>
                📁 {f.filename}
              </span>
            )}
          </div>

          {/* Description */}
          {f.description && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
                Description
              </div>
              <p style={{ margin: 0, fontSize: 13, color: 'var(--text-primary)', lineHeight: 1.6 }}>
                {f.description}
              </p>
            </div>
          )}

          {/* Evidence */}
          {f.evidence && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 4 }}>
                PCAP Evidence
              </div>
              <div style={{
                fontSize: 12, fontFamily: 'monospace',
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: 7, padding: '0.5rem 0.75rem',
                color: 'var(--text-secondary)', lineHeight: 1.5,
              }}>
                🔗 {f.evidence}
              </div>
            </div>
          )}

          {/* Recommendation */}
          {f.recommendation && (
            <div style={{
              backgroundColor: 'var(--blue-light)',
              border: '1px solid var(--blue-border)',
              borderRadius: 8, padding: '0.625rem 0.875rem',
            }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--blue)', textTransform: 'uppercase', letterSpacing: '0.07em', marginBottom: 3 }}>
                Recommendation
              </div>
              <p style={{ margin: 0, fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.55 }}>
                {f.recommendation}
              </p>
            </div>
          )}

          {/* Risk contribution */}
          {f.risk_contribution !== undefined && f.risk_contribution !== null && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
              Risk contribution: <strong style={{ color: 'var(--text-secondary)' }}>{f.risk_contribution}</strong>
            </div>
          )}

          {/* Navigate */}
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onNavigate}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                padding: '0.4rem 0.875rem', borderRadius: 7,
                border: '1px solid var(--blue-border)',
                backgroundColor: 'var(--blue-light)',
                color: 'var(--blue)', fontSize: 12, fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              View Analysis <ArrowRight size={12} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Small reusable sub-components
// ─────────────────────────────────────────────────────────────
function FilterSelect({ label, value, options, onChange }) {
  return (
    <div style={{ position: 'relative', flexShrink: 0 }}>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        style={{
          appearance: 'none',
          padding: '0.4rem 2rem 0.4rem 0.75rem',
          border: '1px solid var(--border)', borderRadius: 7,
          backgroundColor: 'var(--bg-surface)', color: 'var(--text-primary)',
          fontSize: 12, cursor: 'pointer',
        }}
      >
        {options.map((o) => <option key={o} value={o}>{label !== 'Sort' ? `${label}: ` : ''}{o}</option>)}
      </select>
      <ChevronDown size={11} style={{
        position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
        pointerEvents: 'none', color: 'var(--text-muted)',
      }} />
    </div>
  );
}

function LoadingState() {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', gap: 10, color: 'var(--text-muted)', fontSize: 13 }}>
      <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
      Loading findings…
    </div>
  );
}

function ErrorState({ message }) {
  return (
    <div style={{
      padding: '1rem', borderRadius: 10,
      backgroundColor: 'var(--red-light)', border: '1px solid var(--red-border)',
      color: 'var(--red-text)', fontSize: 13,
      display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <AlertTriangle size={16} /> {message}
    </div>
  );
}

function EmptyState({ icon, title, body, action }) {
  const navigate = useNavigate();
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      padding: '3rem 1.5rem', textAlign: 'center', gap: 10,
      backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
    }}>
      {icon}
      <p style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</p>
      <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)', maxWidth: 340 }}>{body}</p>
      {action && (
        <button
          type="button"
          onClick={action.onClick}
          style={{
            marginTop: 8, padding: '0.45rem 1rem', borderRadius: 7,
            border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
            color: 'var(--blue)', fontSize: 12, fontWeight: 600, cursor: 'pointer',
          }}
        >
          {action.label}
        </button>
      )}
    </div>
  );
}
