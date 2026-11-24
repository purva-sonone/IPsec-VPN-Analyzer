import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, Filter, Trash2, Eye, Download, ChevronUp, ChevronDown,
  RefreshCw, AlertTriangle, History as HistoryIcon, X, FileText
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate, riskColor, ikeBadgeClass } from '../lib/utils';

const IKE_OPTIONS  = ['All', 'IKEv1', 'IKEv2', 'Unknown'];
const RISK_OPTIONS = ['All', 'Informational', 'Low', 'Medium', 'High', 'Critical'];
const ML_OPTIONS   = ['All', 'C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP', 'Not Applicable'];

function DeleteModal({ filename, onConfirm, onCancel }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: 'rgba(15, 23, 42, 0.65)',
      backdropFilter: 'blur(3px)',
      padding: '1rem',
    }}>
      <div className="card" style={{ padding: '1.5rem', maxWidth: 420, width: '100%', boxShadow: 'var(--shadow-md)', backgroundColor: 'var(--bg-card)', borderColor: 'var(--border)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.875rem', marginBottom: '1.25rem' }}>
          <div style={{ padding: '0.5rem', backgroundColor: 'var(--red-light)', borderRadius: 8, flexShrink: 0 }}>
            <Trash2 style={{ width: 18, height: 18, color: 'var(--red)' }} />
          </div>
          <div>
            <h3 style={{ fontSize: 15, fontWeight: 700, color: 'var(--text-primary)', margin: 0, marginBottom: 4 }}>
              Delete Analysis Record?
            </h3>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              This will permanently delete the telemetry and report record for{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{filename}</strong>. This cannot be undone.
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} className="btn-secondary" style={{ fontSize: 13 }}>
            Cancel
          </button>
          <button
            onClick={onConfirm}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 6, padding: '0.5rem 1rem',
              borderRadius: 8, backgroundColor: 'var(--red)', color: 'white',
              fontSize: 13, fontWeight: 600, border: 'none', cursor: 'pointer',
            }}
          >
            <Trash2 style={{ width: 13, height: 13 }} /> Delete Record
          </button>
        </div>
      </div>
    </div>
  );
}

export default function HistoryPage() {
  const navigate = useNavigate();
  const [rows,    setRows]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [query,   setQuery]   = useState('');
  const [ikeF,    setIkeF]    = useState('All');
  const [riskF,   setRiskF]   = useState('All');
  const [mlF,     setMlF]     = useState('All');
  const [sortKey, setSortKey] = useState('created_at');
  const [sortDir, setSortDir] = useState('desc');
  const [toDelete, setToDelete] = useState(null);
  const [page, setPage] = useState(1);
  const PER_PAGE = 15;

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const data = await api.history();
      setRows(Array.isArray(data) ? data : []);
    } catch {
      setError('Failed to load analysis history. Please check if backend API is online.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async () => {
    if (!toDelete) return;
    try {
      await api.deleteById(toDelete.id);
      setRows(r => r.filter(x => x.id !== toDelete.id));
    } catch {
      alert('Failed to delete capture record.');
    } finally {
      setToDelete(null);
    }
  };

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    else { setSortKey(key); setSortDir('desc'); }
    setPage(1);
  };

  const filtered = rows
    .filter(r => {
      if (query  && !r.filename?.toLowerCase().includes(query.toLowerCase())) return false;
      if (ikeF  !== 'All' && r.ike_version !== ikeF) return false;
      if (riskF !== 'All' && r.risk_level  !== riskF) return false;
      if (mlF   !== 'All' && r.predicted_category !== mlF) return false;
      return true;
    })
    .sort((a, b) => {
      const av = a[sortKey] ?? '';
      const bv = b[sortKey] ?? '';
      const cmp = String(av).localeCompare(String(bv), undefined, { numeric: true });
      return sortDir === 'asc' ? cmp : -cmp;
    });

  const totalPages = Math.max(1, Math.ceil(filtered.length / PER_PAGE));
  const paged = filtered.slice((page - 1) * PER_PAGE, page * PER_PAGE);

  const SortIcon = ({ col }) =>
    sortKey === col
      ? sortDir === 'asc'
        ? <ChevronUp style={{ width: 12, height: 12, display: 'inline' }} />
        : <ChevronDown style={{ width: 12, height: 12, display: 'inline' }} />
      : null;

  const clearFilters = () => { setQuery(''); setIkeF('All'); setRiskF('All'); setMlF('All'); setPage(1); };
  const hasFilters = query || ikeF !== 'All' || riskF !== 'All' || mlF !== 'All';

  return (
    <div className="page-content">
      {toDelete && (
        <DeleteModal filename={toDelete.filename} onConfirm={handleDelete} onCancel={() => setToDelete(null)} />
      )}

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8, margin: 0, letterSpacing: '-0.02em' }}>
            <HistoryIcon style={{ width: 22, height: 22, color: 'var(--blue)' }} />
            Analysis History
          </h1>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4, marginBottom: 0 }}>
            {rows.length} packet capture analyses stored in local SQLite database
          </p>
        </div>
        <button onClick={load} className="btn-secondary" style={{ fontSize: 13 }}>
          <RefreshCw style={{ width: 13, height: 13 }} /> Refresh History
        </button>
      </div>

      {/* ── Error Banner ──────────────────────────────────────────────── */}
      {error && (
        <div className="alert-error" style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <AlertTriangle style={{ width: 16, height: 16, color: 'var(--red)', flexShrink: 0, marginTop: 1 }} />
          <p style={{ fontSize: 13, color: 'var(--red)', margin: 0 }}>{error}</p>
        </div>
      )}

      {/* ── Filters Bar ────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '1rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.875rem', alignItems: 'flex-end' }}>
          {/* Search */}
          <div style={{ position: 'relative', flex: '1 1 220px' }}>
            <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 14, height: 14, color: 'var(--text-muted)' }} />
            <input
              value={query}
              onChange={e => { setQuery(e.target.value); setPage(1); }}
              placeholder="Search captures by filename…"
              className="input-field"
              style={{ paddingLeft: '2.1rem', fontSize: 13 }}
            />
          </div>

          {/* Filter selects */}
          {[
            ['IKE Version', ikeF, setIkeF, IKE_OPTIONS],
            ['Risk Level',  riskF, setRiskF, RISK_OPTIONS],
            ['ML Category', mlF,   setMlF,  ML_OPTIONS],
          ].map(([label, val, setter, opts]) => (
            <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', paddingLeft: 2 }}>
                {label}
              </span>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 6,
                border: '1px solid var(--border)', borderRadius: 8,
                padding: '0.35rem 0.65rem', backgroundColor: 'var(--bg-surface)',
              }}>
                <Filter style={{ width: 12, height: 12, color: 'var(--text-muted)' }} />
                <select
                  value={val}
                  onChange={e => { setter(e.target.value); setPage(1); }}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    fontSize: 13,
                    color: 'var(--text-primary)',
                    cursor: 'pointer',
                    outline: 'none',
                  }}
                >
                  {opts.map(o => (
                    <option key={o} value={o} style={{ backgroundColor: 'var(--bg-card)', color: 'var(--text-primary)' }}>
                      {o}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          ))}

          {hasFilters && (
            <button
              onClick={clearFilters}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                fontSize: 12, color: 'var(--text-muted)',
                background: 'none', border: 'none',
                cursor: 'pointer', paddingBottom: '0.5rem',
              }}
            >
              <X style={{ width: 13, height: 13 }} /> Reset filters
            </button>
          )}
        </div>
      </div>

      {/* ── Data Table ─────────────────────────────────────────────────── */}
      <div className="card" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4rem', gap: 8, color: 'var(--text-muted)', fontSize: 13 }}>
            <RefreshCw style={{ width: 16, height: 16, animation: 'spin 1s linear infinite' }} />
            <span>Loading analysis records…</span>
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '4rem 1rem', gap: '0.75rem' }}>
            <div style={{ padding: '1.25rem', borderRadius: 12, backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
              <HistoryIcon style={{ width: 34, height: 34, color: 'var(--text-muted)' }} />
            </div>
            <p style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
              {hasFilters ? 'No analysis records match the selected filters.' : 'No analyses found. Upload a PCAP file to get started.'}
            </p>
            <p style={{ fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
              Upload a PCAP capture to generate security findings and traffic classification.
            </p>
            {!hasFilters && (
              <button onClick={() => navigate('/upload')} className="btn-primary" style={{ fontSize: 13, marginTop: 6 }}>
                Upload PCAP File
              </button>
            )}
          </div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    {[
                      ['filename',          'Capture File'],
                      ['created_at',        'Analysis Date'],
                      ['packet_count',      'Packets'],
                      ['ike_version',       'IKE'],
                      ['protocols',         'Protocols'],
                      ['vpn_mode',          'VPN Mode'],
                      ['risk_score',        'Risk Level'],
                      ['predicted_category','ML Category'],
                      ['confidence_score',  'Confidence'],
                      ['',                  'Actions'],
                    ].map(([key, label]) => (
                      <th
                        key={label}
                        className={key ? 'sortable' : ''}
                        onClick={() => key && toggleSort(key)}
                      >
                        {label} {key && <SortIcon col={key} />}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {paged.map(row => {
                    const rc   = riskColor(row.risk_level);
                    const conf = row.confidence_score != null ? `${(row.confidence_score * 100).toFixed(1)}%` : '—';
                    const vpn  = row.vpn_mode?.startsWith('Tunnel') ? 'Tunnel'
                               : row.vpn_mode?.startsWith('Transport') ? 'Transport' : 'Not Extracted';
                    const isNA = !row.predicted_category || row.predicted_category === 'Not Applicable';
                    return (
                      <tr key={row.id}>
                        <td className="td-primary" style={{ maxWidth: 170 }}>
                          <span
                            style={{
                              display: 'block',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              color: 'var(--text-primary)',
                              fontWeight: 600,
                            }}
                            title={row.filename}
                          >
                            {row.filename}
                          </span>
                        </td>
                        <td style={{ fontSize: 11, whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                          {fmtDate(row.created_at)}
                        </td>
                        <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                          {row.packet_count ?? '—'}
                        </td>
                        <td>
                          <span className={ikeBadgeClass(row.ike_version)}>{row.ike_version || '—'}</span>
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {row.protocols || '—'}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {vpn}
                        </td>
                        <td>
                          <span className={`badge ${rc.badge}`}>{row.risk_level || '—'}</span>
                        </td>
                        <td>
                          {isNA ? (
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>N/A</span>
                          ) : (
                            <span className="badge badge-ml">{row.predicted_category}</span>
                          )}
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                          {conf}
                        </td>
                        <td>
                          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                            <button
                              onClick={() => navigate(`/analysis/${row.id}`)}
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                                padding: '0.3rem 0.625rem',
                                borderRadius: 6,
                                backgroundColor: 'var(--blue-light)',
                                border: '1px solid var(--blue-border)',
                                color: 'var(--blue-text)',
                                fontSize: 11,
                                fontWeight: 600,
                                cursor: 'pointer',
                              }}
                            >
                              <Eye style={{ width: 12, height: 12 }} /> View
                            </button>
                            <a
                              href={api.reportUrl(row.id)}
                              target="_blank"
                              rel="noreferrer"
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: 4,
                                padding: '0.3rem 0.625rem',
                                borderRadius: 6,
                                backgroundColor: 'var(--bg-surface)',
                                border: '1px solid var(--border)',
                                color: 'var(--text-secondary)',
                                fontSize: 11,
                                fontWeight: 600,
                                textDecoration: 'none',
                              }}
                            >
                              <Download style={{ width: 12, height: 12 }} /> PDF
                            </a>
                            <button
                              onClick={() => setToDelete(row)}
                              title="Delete record"
                              style={{
                                display: 'inline-flex',
                                alignItems: 'center',
                                padding: '0.35rem',
                                borderRadius: 6,
                                backgroundColor: 'var(--red-light)',
                                border: '1px solid var(--red-border)',
                                color: 'var(--red-text)',
                                cursor: 'pointer',
                              }}
                            >
                              <Trash2 style={{ width: 13, height: 13 }} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '0.875rem 1.25rem',
                borderTop: '1px solid var(--border)',
                fontSize: 12,
                color: 'var(--text-muted)',
                backgroundColor: 'var(--bg-surface)',
              }}>
                <span style={{ fontWeight: 500, color: 'var(--text-secondary)' }}>
                  Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, filtered.length)} of {filtered.length} analyses
                </span>
                <div style={{ display: 'flex', gap: 4 }}>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                    <button
                      key={p}
                      onClick={() => setPage(p)}
                      style={{
                        minWidth: 28,
                        height: 28,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        borderRadius: 6,
                        fontSize: 12,
                        fontWeight: 600,
                        border: '1px solid var(--border)',
                        cursor: 'pointer',
                        backgroundColor: p === page ? 'var(--blue)' : 'var(--bg-card)',
                        color: p === page ? '#FFFFFF' : 'var(--text-secondary)',
                      }}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
