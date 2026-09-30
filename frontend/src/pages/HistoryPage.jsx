import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search, Filter, Trash2, Eye, Download, ChevronUp, ChevronDown,
  RefreshCw, AlertTriangle, History as HistoryIcon, X,
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate, riskColor, ikeBadgeClass } from '../lib/utils';

const IKE_OPTIONS  = ['All', 'IKEv1', 'IKEv2', 'Unknown'];
const RISK_OPTIONS = ['All', 'Informational', 'Low', 'Medium', 'High', 'Critical'];
const ML_OPTIONS   = ['All', 'C2', 'CHAT', 'FILE_TRANSFER', 'STREAMING', 'VOIP', 'Not Applicable'];

function DeleteModal({ filename, onConfirm, onCancel }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 50,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: 'rgba(15, 23, 42, 0.4)',
      backdropFilter: 'blur(2px)',
    }}>
      <div className="card" style={{ padding: '1.5rem', maxWidth: 380, width: '100%', margin: '0 1rem', boxShadow: '0 20px 40px rgba(15,23,42,0.15)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.75rem', marginBottom: '1.25rem' }}>
          <div style={{ padding: '0.5rem', backgroundColor: '#FEF2F2', borderRadius: 8, flexShrink: 0 }}>
            <Trash2 style={{ width: 16, height: 16, color: '#B91C1C' }} />
          </div>
          <div>
            <h3 style={{ fontSize: 14, fontWeight: 600, color: '#0F172A', marginBottom: 4 }}>Delete Analysis?</h3>
            <p style={{ fontSize: 12, color: '#64748B', lineHeight: 1.6 }}>
              This will permanently remove the analysis record for{' '}
              <strong style={{ color: '#0F172A' }}>{filename}</strong>.
              This action cannot be undone.
            </p>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} className="btn-secondary" style={{ fontSize: 13 }}>Cancel</button>
          <button onClick={onConfirm} style={{
            display: 'inline-flex', alignItems: 'center', gap: 6, padding: '0.5rem 1rem',
            borderRadius: 8, backgroundColor: '#DC2626', color: 'white',
            fontSize: 13, fontWeight: 500, border: 'none', cursor: 'pointer',
          }}>
            <Trash2 style={{ width: 13, height: 13 }} /> Delete
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
    try { setRows(await api.history()); }
    catch { setError('Failed to load history. Backend may be offline.'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async () => {
    if (!toDelete) return;
    try {
      await api.deleteById(toDelete.id);
      setRows(r => r.filter(x => x.id !== toDelete.id));
    } catch { alert('Failed to delete.'); }
    finally { setToDelete(null); }
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
      ? sortDir === 'asc' ? <ChevronUp style={{ width: 11, height: 11, display: 'inline' }} /> : <ChevronDown style={{ width: 11, height: 11, display: 'inline' }} />
      : null;

  const clearFilters = () => { setQuery(''); setIkeF('All'); setRiskF('All'); setMlF('All'); setPage(1); };
  const hasFilters = query || ikeF !== 'All' || riskF !== 'All' || mlF !== 'All';

  return (
    <div className="page-content">
      {toDelete && (
        <DeleteModal filename={toDelete.filename} onConfirm={handleDelete} onCancel={() => setToDelete(null)} />
      )}

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#0F172A', display: 'flex', alignItems: 'center', gap: 8, margin: 0 }}>
            <HistoryIcon style={{ width: 18, height: 18, color: '#2563EB' }} />
            Analysis History
          </h1>
          <p style={{ fontSize: 13, color: '#64748B', marginTop: 4 }}>{rows.length} total analyses</p>
        </div>
        <button onClick={load} className="btn-secondary" style={{ fontSize: 13 }}>
          <RefreshCw style={{ width: 13, height: 13 }} /> Refresh
        </button>
      </div>

      {/* ── Error ──────────────────────────────────────────────────────── */}
      {error && (
        <div className="alert-error">
          <AlertTriangle style={{ width: 15, height: 15, color: '#B91C1C', flexShrink: 0, marginTop: 1 }} />
          <p style={{ fontSize: 13, color: '#B91C1C' }}>{error}</p>
        </div>
      )}

      {/* ── Filters ────────────────────────────────────────────────────── */}
      <div className="card" style={{ padding: '0.875rem 1rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'flex-end' }}>
          {/* Search */}
          <div style={{ position: 'relative', flex: '1 1 200px' }}>
            <Search style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', width: 13, height: 13, color: '#94A3B8' }} />
            <input
              value={query}
              onChange={e => { setQuery(e.target.value); setPage(1); }}
              placeholder="Search by filename…"
              className="input-field"
              style={{ paddingLeft: '2rem', fontSize: 13 }}
            />
          </div>

          {/* Filter selects */}
          {[
            ['IKE Version', ikeF, setIkeF, IKE_OPTIONS],
            ['Risk Level',  riskF, setRiskF, RISK_OPTIONS],
            ['ML Category', mlF,   setMlF,  ML_OPTIONS],
          ].map(([label, val, setter, opts]) => (
            <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', paddingLeft: 2 }}>
                {label}
              </span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, border: '1px solid #E2E8F0', borderRadius: 8, padding: '0.4rem 0.75rem', backgroundColor: '#FFFFFF' }}>
                <Filter style={{ width: 12, height: 12, color: '#94A3B8' }} />
                <select
                  value={val}
                  onChange={e => { setter(e.target.value); setPage(1); }}
                  style={{ background: 'transparent', border: 'none', fontSize: 13, color: '#0F172A', cursor: 'pointer', outline: 'none' }}>
                  {opts.map(o => <option key={o}>{o}</option>)}
                </select>
              </div>
            </div>
          ))}

          {hasFilters && (
            <button onClick={clearFilters}
              style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: '#64748B', background: 'none', border: 'none', cursor: 'pointer', paddingTop: '1.25rem' }}>
              <X style={{ width: 12, height: 12 }} /> Clear filters
            </button>
          )}
        </div>
      </div>

      {/* ── Table ──────────────────────────────────────────────────────── */}
      <div className="card" style={{ overflow: 'hidden' }}>
        {loading ? (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4rem', gap: 8, color: '#94A3B8', fontSize: 13 }}>
            <RefreshCw style={{ width: 14, height: 14 }} /> Loading history…
          </div>
        ) : filtered.length === 0 ? (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '4rem 1rem', gap: '0.75rem' }}>
            <div style={{ padding: '1.25rem', borderRadius: 12, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
              <HistoryIcon style={{ width: 32, height: 32, color: '#CBD5E1' }} />
            </div>
            <p style={{ fontSize: 13, color: '#64748B' }}>
              {hasFilters ? 'No results match your filters.' : 'No analyses yet.'}
            </p>
          </div>
        ) : (
          <>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    {[
                      ['filename',          'File'],
                      ['created_at',        'Date'],
                      ['packet_count',      'Pkts'],
                      ['ike_version',       'IKE'],
                      ['protocols',         'Protocols'],
                      ['vpn_mode',          'VPN Mode'],
                      ['risk_score',        'Risk'],
                      ['predicted_category','ML Category'],
                      ['confidence_score',  'Confidence'],
                      ['',                  'Actions'],
                    ].map(([key, label]) => (
                      <th key={label}
                        className={key ? 'sortable' : ''}
                        onClick={() => key && toggleSort(key)}>
                        {label} <SortIcon col={key} />
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
                        <td className="td-primary" style={{ maxWidth: 160 }}>
                          <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.filename}>
                            {row.filename}
                          </span>
                        </td>
                        <td style={{ fontSize: 11, whiteSpace: 'nowrap' }}>{fmtDate(row.created_at)}</td>
                        <td style={{ fontSize: 12 }}>{row.packet_count ?? '—'}</td>
                        <td>
                          <span className={ikeBadgeClass(row.ike_version)}>{row.ike_version || '—'}</span>
                        </td>
                        <td style={{ fontSize: 11 }}>{row.protocols || '—'}</td>
                        <td style={{ fontSize: 11 }}>{vpn}</td>
                        <td>
                          <span className={`badge ${rc.badge}`}>{row.risk_level || '—'}</span>
                        </td>
                        <td>
                          {isNA
                            ? <span style={{ fontSize: 11, color: '#94A3B8' }}>N/A</span>
                            : <span className="badge badge-ml">{row.predicted_category}</span>
                          }
                        </td>
                        <td style={{ fontSize: 11 }}>{conf}</td>
                        <td>
                          <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                            <button onClick={() => navigate(`/analysis/${row.id}`)}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '0.3rem 0.625rem', borderRadius: 5, backgroundColor: '#EFF6FF', border: '1px solid #BFDBFE', color: '#1D4ED8', fontSize: 11, fontWeight: 600, cursor: 'pointer' }}>
                              <Eye style={{ width: 11, height: 11 }} /> View
                            </button>
                            <a href={api.reportUrl(row.id)} target="_blank" rel="noreferrer"
                              style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '0.3rem 0.625rem', borderRadius: 5, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', color: '#64748B', fontSize: 11, fontWeight: 600, textDecoration: 'none' }}>
                              <Download style={{ width: 11, height: 11 }} /> PDF
                            </a>
                            <button onClick={() => setToDelete(row)} title="Delete"
                              style={{ display: 'inline-flex', alignItems: 'center', padding: '0.3rem', borderRadius: 5, backgroundColor: '#FEF2F2', border: '1px solid #FECACA', color: '#B91C1C', cursor: 'pointer' }}>
                              <Trash2 style={{ width: 12, height: 12 }} />
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
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 1.25rem', borderTop: '1px solid #E2E8F0', fontSize: 12, color: '#64748B', backgroundColor: '#FAFBFC' }}>
                <span style={{ fontWeight: 500 }}>
                  Showing {(page - 1) * PER_PAGE + 1}–{Math.min(page * PER_PAGE, filtered.length)} of {filtered.length}
                </span>
                <div style={{ display: 'flex', gap: 4 }}>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
                    <button key={p} onClick={() => setPage(p)}
                      style={{
                        minWidth: 28, height: 28, display: 'flex', alignItems: 'center', justifyContent: 'center',
                        borderRadius: 5, fontSize: 12, fontWeight: 500, border: 'none', cursor: 'pointer',
                        backgroundColor: p === page ? '#2563EB' : '#F1F5F9',
                        color: p === page ? 'white' : '#475569',
                      }}>
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
