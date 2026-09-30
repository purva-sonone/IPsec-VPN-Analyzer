import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, UploadCloud, History, TrendingUp, AlertTriangle,
  CheckCircle, Cpu, RefreshCw, ChevronRight, Activity,
  Wifi, Server, Terminal, Database, XCircle, FileText, BarChart2
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate, riskColor, ikeBadgeClass } from '../lib/utils';

// ── Design-token-aligned color maps ────────────────────────────────────────
const COLOR_RISK = {
  High: '#DC2626', Critical: '#DC2626',
  Medium: '#D97706',
  Low: '#2563EB',
  Informational: '#16A34A',
  Unknown: '#94A3B8',
};
const COLOR_IKE = { IKEv2: '#2563EB', IKEv1: '#D97706', Unknown: '#94A3B8' };
const COLOR_VPN = { Tunnel: '#2563EB', Transport: '#7C3AED', 'Not Extracted': '#94A3B8' };
const COLOR_ML  = {
  C2: '#DC2626', CHAT: '#2563EB', FILE_TRANSFER: '#16A34A',
  STREAMING: '#D97706', VOIP: '#7C3AED', 'Not Applicable': '#94A3B8',
};

// ── Stat Card ──────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, accent = '#2563EB', accentBg = '#EFF6FF' }) {
  return (
    <div className="stat-card">
      <div style={{
        display: 'inline-flex', padding: '0.5rem', borderRadius: 8,
        backgroundColor: accentBg, marginBottom: '0.375rem', width: 'fit-content',
      }}>
        <Icon style={{ width: 15, height: 15, color: accent }} />
      </div>
      <p style={{ fontSize: '1.625rem', fontWeight: 700, color: '#0F172A', lineHeight: 1.1 }}>
        {value ?? '—'}
      </p>
      <p style={{ fontSize: 11, fontWeight: 500, color: '#64748B', marginTop: 2 }}>{label}</p>
      {sub && <p style={{ fontSize: 11, color: '#94A3B8', marginTop: 2 }}>{sub}</p>}
    </div>
  );
}

// ── System Health Panel ────────────────────────────────────────────────────
function SystemHealthPanel({ sysDeps, loading }) {
  const ts = sysDeps?.tshark;
  const mg = sysDeps?.mongodb;
  const ml = sysDeps?.ml_model;

  const items = [
    {
      icon: Server, label: 'Backend API',
      ok: !loading && sysDeps !== null,
      loading,
      text: loading ? 'Connecting…' : sysDeps ? 'Connected' : 'Offline',
    },
    {
      icon: Terminal, label: 'TShark Engine',
      ok: ts?.available === true,
      loading,
      text: loading ? 'Checking…' : ts?.available
        ? `Ready — ${ts.version?.split('(')[0]?.trim() || 'found'}`
        : 'Not Found — Install Wireshark',
      warn: !loading && ts?.available === false,
    },
    {
      icon: Cpu, label: 'ML Classifier',
      ok: ml?.available === true,
      loading,
      text: loading ? 'Checking…' : ml?.available ? 'Ready' : 'Model not found',
    },
    {
      icon: Database, label: 'Database',
      ok: mg?.available === true,
      loading,
      text: loading ? 'Checking…' : mg?.available ? 'Connected' : 'Unavailable',
    },
  ];

  return (
    <div className="card" style={{ overflow: 'hidden' }}>
      <div className="card-header">
        <Activity style={{ width: 14, height: 14, color: '#2563EB' }} />
        <span className="card-header-title">System Health</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        {items.map(({ icon: Icon, label, ok, loading: l, text, warn }) => (
          <div key={label} style={{
            padding: '0.875rem 1.25rem',
            borderRight: '1px solid #E2E8F0',
            borderBottom: '1px solid #E2E8F0',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
              <Icon style={{ width: 13, height: 13, color: '#94A3B8', flexShrink: 0 }} />
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8' }}>
                {label}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              {l
                ? <span className="status-dot-idle" />
                : ok
                  ? <span className="status-dot-ok" />
                  : warn
                    ? <span className="status-dot-warn" />
                    : <span className="status-dot-error" />
              }
              <span style={{
                fontSize: 12, fontWeight: 500,
                color: l ? '#94A3B8' : ok ? '#15803D' : warn ? '#B45309' : '#B91C1C',
              }} title={text}>
                {text.length > 42 ? text.substring(0, 39) + '…' : text}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Empty State ────────────────────────────────────────────────────────────
function EmptyState({ onAnalyze, title = 'No Analysis History', desc = 'Upload a PCAP file to begin your first security analysis.' }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '4rem 1rem', gap: '1rem', textAlign: 'center' }}>
      <div style={{ padding: '1.25rem', borderRadius: 14, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
        <Shield style={{ width: 36, height: 36, color: '#94A3B8' }} />
      </div>
      <div>
        <h3 style={{ fontSize: 15, fontWeight: 600, color: '#0F172A', marginBottom: 6 }}>{title}</h3>
        <p style={{ fontSize: 13, color: '#64748B', maxWidth: 280 }}>{desc}</p>
      </div>
      {onAnalyze && (
        <button onClick={onAnalyze} className="btn-primary" style={{ marginTop: 8 }}>
          <UploadCloud style={{ width: 14, height: 14 }} /> Analyze New PCAP
        </button>
      )}
    </div>
  );
}

// ── Aggregate stats from history ───────────────────────────────────────────
function buildStatsMap(rows) {
  const riskMap = {}, ikeMap = {}, vpnMap = {}, mlMap = {};
  let ipsecCount = 0, mlCount = 0, highRiskCount = 0;
  rows.forEach(r => {
    const rl = r.risk_level || 'Unknown';
    riskMap[rl] = (riskMap[rl] || 0) + 1;
    if (rl === 'High' || rl === 'Critical') highRiskCount++;
    const iv = r.ike_version || 'Unknown';
    ikeMap[iv] = (ikeMap[iv] || 0) + 1;
    let vm = 'Not Extracted';
    if (r.vpn_mode && r.vpn_mode !== 'Unknown')
      vm = r.vpn_mode.startsWith('Tunnel') ? 'Tunnel' : r.vpn_mode.startsWith('Transport') ? 'Transport' : 'Not Extracted';
    vpnMap[vm] = (vpnMap[vm] || 0) + 1;
    const ml = r.predicted_category || 'Not Applicable';
    if (ml !== 'Not Applicable') mlCount++;
    mlMap[ml] = (mlMap[ml] || 0) + 1;
    if (r.protocols && (r.protocols.includes('IKE') || r.protocols.includes('ESP'))) ipsecCount++;
  });
  return { riskMap, ikeMap, vpnMap, mlMap, ipsecCount, mlCount, highRiskCount };
}

// ── Distribution Bar ───────────────────────────────────────────────────────
function DistributionBar({ title, dataMap, colorMap }) {
  const total = Object.values(dataMap).reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const items = Object.entries(dataMap).sort((a, b) => b[1] - a[1]);

  return (
    <div style={{ marginBottom: '1.25rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#0F172A' }}>{title}</span>
        <span style={{ fontSize: 11, color: '#94A3B8' }}>{total} total</span>
      </div>
      <div className="dist-bar-track" style={{ marginBottom: 8 }}>
        {items.map(([key, val]) => (
          <div key={key}
            style={{ width: `${(val / total) * 100}%`, backgroundColor: colorMap[key] || '#94A3B8' }}
            title={`${key}: ${val}`}
          />
        ))}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 16px' }}>
        {items.map(([key, val]) => (
          <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: colorMap[key] || '#94A3B8', flexShrink: 0 }} />
            <span style={{ fontSize: 11, color: '#475569' }}>
              {key} <span style={{ fontWeight: 600, color: '#0F172A' }}>{val}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Dashboard ─────────────────────────────────────────────────────────
export default function Dashboard() {
  const navigate = useNavigate();
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [sysDeps, setSysDeps] = useState(null);
  const [depsLoading, setDepsLoading] = useState(true);

  const load = async () => {
    setLoading(true); setError(null); setDepsLoading(true);
    api.systemDeps().then(setSysDeps).catch(() => setSysDeps(null)).finally(() => setDepsLoading(false));
    try {
      const h = await api.history();
      setHistory(h);
    } catch {
      setError('Cannot connect to backend. Make sure the server is running on port 8000.');
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const agg    = buildStatsMap(history);
  const recent = history.slice(0, 6);
  const latest = history.length > 0 ? history[0] : null;

  return (
    <div className="page-content">

      {/* ── Page Header ───────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 style={{ fontSize: '1.375rem', fontWeight: 700, color: '#0F172A', margin: 0 }}>
            Security Overview
          </h1>
          <p style={{ fontSize: 13, color: '#64748B', marginTop: 4 }}>
            Monitor PCAP analyses, security findings and encrypted traffic classifications.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button onClick={load} className="btn-secondary" style={{ fontSize: 13 }}>
            <RefreshCw style={{ width: 13, height: 13 }} /> Refresh
          </button>
          <button onClick={() => navigate('/upload')} className="btn-primary" style={{ fontSize: 13 }}>
            <UploadCloud style={{ width: 14, height: 14 }} /> Analyze New PCAP
          </button>
        </div>
      </div>

      {/* ── Error Banner ──────────────────────────────────────────────── */}
      {error && (
        <div className="alert-error">
          <AlertTriangle style={{ width: 15, height: 15, color: '#B91C1C', flexShrink: 0, marginTop: 1 }} />
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#B91C1C', marginBottom: 2 }}>Backend Offline</p>
            <p style={{ fontSize: 12, color: '#DC2626' }}>{error}</p>
            <button onClick={load} style={{ marginTop: 6, fontSize: 12, color: '#B91C1C', textDecoration: 'underline', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>
              Retry Connection
            </button>
          </div>
        </div>
      )}

      {/* ── System Health ─────────────────────────────────────────────── */}
      <SystemHealthPanel sysDeps={sysDeps} loading={depsLoading} />

      {/* ── KPI Stats ─────────────────────────────────────────────────── */}
      {!error && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '1rem' }}>
          <StatCard icon={BarChart2}    label="Total Analyses"  value={loading ? '…' : history.length}
            accent="#2563EB" accentBg="#EFF6FF" />
          <StatCard icon={Shield}       label="IPsec Detected"  value={loading ? '…' : `${agg.ipsecCount} / ${history.length}`}
            accent="#2563EB" accentBg="#EFF6FF" />
          <StatCard icon={AlertTriangle} label="High Risk"      value={loading ? '…' : agg.highRiskCount}
            accent={agg.highRiskCount > 0 ? '#DC2626' : '#16A34A'}
            accentBg={agg.highRiskCount > 0 ? '#FEF2F2' : '#F0FDF4'} />
          <StatCard icon={Cpu}          label="ML Classified"   value={loading ? '…' : `${agg.mlCount} / ${history.length}`}
            accent="#7C3AED" accentBg="#F5F3FF" />
          <StatCard icon={History}      label="Last Analysis"   value={loading ? '…' : (latest ? fmtDate(latest.created_at) : 'None')}
            sub={latest?.filename}
            accent="#64748B" accentBg="#F8FAFC" />
        </div>
      )}

      {/* ── Latest Analysis + Security Overview Row ────────────────────── */}
      {!error && history.length > 0 && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1rem' }} className="lg-grid-auto">

          {/* Latest Analysis Card */}
          <div className="card" style={{ display: 'flex', flexDirection: 'column', gridColumn: 'span 1' }}>
            <div className="card-header" style={{ borderBottom: '1px solid #E2E8F0' }}>
              <FileText style={{ width: 14, height: 14, color: '#2563EB' }} />
              <span className="card-header-title">Latest Analysis</span>
            </div>
            <div style={{ padding: '1.125rem', flex: 1 }}>
              {/* File name & meta */}
              <div style={{ marginBottom: '1rem', paddingBottom: '0.875rem', borderBottom: '1px solid #F1F5F9' }}>
                <p style={{ fontSize: 13, fontWeight: 600, color: '#0F172A', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={latest.filename}>
                  {latest.filename}
                </p>
                <p style={{ fontSize: 11, color: '#94A3B8', marginTop: 3 }}>
                  {fmtDate(latest.created_at)} · {latest.packet_count ?? '—'} packets
                </p>
              </div>

              {/* Metadata grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.625rem 1rem' }}>
                {[
                  ['IKE Version', latest.ike_version || 'Unknown'],
                  ['Protocols',   latest.protocols   || 'Unknown'],
                  ['VPN Mode',    latest.vpn_mode?.startsWith('Tunnel') ? 'Tunnel' : latest.vpn_mode?.startsWith('Transport') ? 'Transport' : 'Not Extracted'],
                  ['Encryption',  latest.encryption  || 'Not Extracted'],
                  ['DH Group',    latest.key_exchange || 'Not Extracted'],
                  ['Auth',        latest.authentication || 'Not Extracted'],
                ].map(([lbl, val]) => (
                  <div key={lbl}>
                    <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94A3B8', display: 'block', marginBottom: 2 }}>
                      {lbl}
                    </span>
                    <span style={{ fontSize: 12, color: '#0F172A', fontWeight: 500 }} title={val}>
                      {val.length > 22 ? val.substring(0, 20) + '…' : val}
                    </span>
                  </div>
                ))}
                <div>
                  <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94A3B8', display: 'block', marginBottom: 2 }}>Risk</span>
                  <span className={`badge ${riskColor(latest.risk_level).badge}`}>{latest.risk_level || 'Unknown'}</span>
                </div>
                <div>
                  <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94A3B8', display: 'block', marginBottom: 2 }}>ML Class</span>
                  <span style={{ fontSize: 12, color: latest.predicted_category !== 'Not Applicable' ? '#6D28D9' : '#94A3B8', fontWeight: 500 }}>
                    {latest.predicted_category !== 'Not Applicable'
                      ? `${latest.predicted_category} · ${(latest.confidence_score * 100).toFixed(0)}%`
                      : 'N/A'}
                  </span>
                </div>
              </div>
            </div>
            <div style={{ padding: '0.75rem 1.125rem', borderTop: '1px solid #F1F5F9', backgroundColor: '#FAFBFC' }}>
              <button onClick={() => navigate(`/analysis/${latest.id}`)}
                style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 12, fontWeight: 600, color: '#2563EB', background: 'none', border: 'none', cursor: 'pointer' }}>
                View Full Report <ChevronRight style={{ width: 13, height: 13 }} />
              </button>
            </div>
          </div>

          {/* Security Overview Card */}
          <div className="card" style={{ gridColumn: 'span 1' }}>
            <div className="card-header">
              <TrendingUp style={{ width: 14, height: 14, color: '#2563EB' }} />
              <span className="card-header-title">Security Analytics</span>
              <span style={{ fontSize: 11, color: '#94A3B8', marginLeft: 'auto' }}>{history.length} analyses</span>
            </div>
            <div style={{ padding: '1.25rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0 2.5rem' }}>
              <DistributionBar title="Risk Distribution" dataMap={agg.riskMap} colorMap={COLOR_RISK} />
              <DistributionBar title="IKE Version"       dataMap={agg.ikeMap}  colorMap={COLOR_IKE} />
              <DistributionBar title="VPN Mode"          dataMap={agg.vpnMap}  colorMap={COLOR_VPN} />
              <DistributionBar title="ML Categories"     dataMap={agg.mlMap}   colorMap={COLOR_ML} />
            </div>
          </div>
        </div>
      )}

      {/* ── Recent Analyses Table ──────────────────────────────────────── */}
      {!error && (
        <div className="card" style={{ overflow: 'hidden' }}>
          <div className="card-header" style={{ justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <History style={{ width: 14, height: 14, color: '#2563EB' }} />
              <span className="card-header-title">Recent Analyses</span>
            </div>
            {history.length > 0 && (
              <button onClick={() => navigate('/history')}
                style={{ fontSize: 12, fontWeight: 600, color: '#2563EB', background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }}>
                View All <ChevronRight style={{ width: 12, height: 12 }} />
              </button>
            )}
          </div>

          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', gap: 8, color: '#94A3B8' }}>
              <RefreshCw style={{ width: 14, height: 14, animation: 'spin 1s linear infinite' }} /> Loading history…
            </div>
          ) : history.length === 0 ? (
            <EmptyState onAnalyze={() => navigate('/upload')} title="No analyses yet" desc="Upload a PCAP file to begin your first security analysis." />
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    {['File', 'Date', 'Packets', 'IKE', 'Protocols', 'VPN Mode', 'Risk', 'ML Category', 'Action'].map(h => (
                      <th key={h}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {recent.map(row => {
                    const rc   = riskColor(row.risk_level);
                    const cat  = row.predicted_category || '—';
                    const isNA = cat === 'Not Applicable' || cat === '—';
                    return (
                      <tr key={row.id}>
                        <td className="td-primary" style={{ maxWidth: 170 }}>
                          <span style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.filename}>
                            {row.filename}
                          </span>
                        </td>
                        <td style={{ whiteSpace: 'nowrap', fontSize: 11 }}>{fmtDate(row.created_at)}</td>
                        <td style={{ fontSize: 12 }}>{row.packet_count ?? '—'}</td>
                        <td>
                          <span className={ikeBadgeClass(row.ike_version)}>{row.ike_version || '—'}</span>
                        </td>
                        <td style={{ fontSize: 11 }}>{row.protocols || '—'}</td>
                        <td style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                          {row.vpn_mode?.startsWith('Tunnel') ? 'Tunnel' : row.vpn_mode?.startsWith('Transport') ? 'Transport' : 'Not Extracted'}
                        </td>
                        <td>
                          <span className={`badge ${rc.badge}`}>{row.risk_level || '—'}</span>
                        </td>
                        <td>
                          {isNA
                            ? <span style={{ fontSize: 11, color: '#94A3B8' }}>N/A</span>
                            : <span className="badge badge-ml">{cat}</span>
                          }
                        </td>
                        <td>
                          <button onClick={() => navigate(`/analysis/${row.id}`)}
                            style={{
                              fontSize: 11, fontWeight: 600, color: '#2563EB',
                              backgroundColor: '#EFF6FF', border: '1px solid #BFDBFE',
                              borderRadius: 5, padding: '0.25rem 0.625rem', cursor: 'pointer',
                            }}>
                            View
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
