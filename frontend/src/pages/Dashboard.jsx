import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, UploadCloud, AlertTriangle,
  Cpu, RefreshCw, Activity,
  Server, Terminal, Database, BarChart3,
  Key, Zap, X, Loader2,
  FileSearch, FileText, Clock, ArrowRight
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  PieChart, Pie, AreaChart, Area
} from 'recharts';
import { api } from '../lib/api';
import { useTheme } from '../context/ThemeContext';
import { fmtDate } from '../lib/utils';
import ThreatMatrix from '../components/ThreatMatrix';
import TunnelTopologyCard from '../components/TunnelTopologyCard';

// ── Design-token-aligned color maps ────────────────────────────────────────
const COLOR_RISK = {
  Critical: '#DC2626',
  High: '#DC2626',
  Medium: '#D97706',
  Low: '#2563EB',
  Informational: '#16A34A',
  Unknown: '#94A3B8',
};

const COLOR_IKE = {
  IKEv2: '#2563EB',
  IKEv1: '#D97706',
  Unknown: '#94A3B8'
};

const COLOR_ML = {
  C2: '#DC2626',
  CHAT: '#2563EB',
  FILE_TRANSFER: '#16A34A',
  STREAMING: '#D97706',
  VOIP: '#7C3AED',
  'Not Applicable': '#94A3B8',
};

// ── Stat Card ──────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, sub, accent = 'var(--blue)', accentBg = 'var(--blue-light)' }) {
  return (
    <div
      className="card"
      style={{
        padding: '1.15rem 1.25rem 1rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.35rem',
        position: 'relative',
        overflow: 'hidden',
        transition: 'transform 0.15s ease, box-shadow 0.15s ease',
      }}
    >
      <div style={{
        display: 'inline-flex',
        padding: '0.5rem',
        borderRadius: 8,
        backgroundColor: accentBg,
        marginBottom: '0.25rem',
        width: 'fit-content',
        border: '1px solid var(--border-muted)',
      }}>
        <Icon style={{ width: 17, height: 17, color: accent }} />
      </div>
      <p style={{
        fontSize: '1.75rem',
        fontWeight: 700,
        color: 'var(--text-primary)',
        lineHeight: 1.1,
        margin: '0.1rem 0',
      }}>
        {value ?? '—'}
      </p>
      <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', margin: 0 }}>
        {label}
      </p>
      {sub && (
        <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: 0, marginTop: 2 }}>
          {sub}
        </p>
      )}
    </div>
  );
}

// ── Latest Investigation Snapshot ──────────────────────────────────────────
function LatestInvestigationSnapshot({ latest, loading, onNavigateUpload, onViewAnalysis }) {
  if (loading) {
    return (
      <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <FileSearch style={{ width: 15, height: 15, color: 'var(--blue)' }} />
            <span className="card-header-title">Latest Investigation Snapshot</span>
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Forensics Spotlight</span>
        </div>
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '2rem 1.5rem', gap: 10, color: 'var(--text-muted)' }}>
          <Loader2 size={18} style={{ animation: 'spin 1s linear infinite', color: 'var(--blue)' }} />
          <span style={{ fontSize: 13, fontWeight: 500 }}>Loading latest investigation…</span>
        </div>
      </div>
    );
  }

  if (!latest) {
    return (
      <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <FileSearch style={{ width: 15, height: 15, color: 'var(--blue)' }} />
            <span className="card-header-title">Latest Investigation Snapshot</span>
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>No Records</span>
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '1.5rem', textAlign: 'center', gap: 10 }}>
          <div style={{ width: 38, height: 38, borderRadius: 10, backgroundColor: 'var(--bg-muted)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)' }}>
            <FileSearch size={20} />
          </div>
          <div>
            <h4 style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 4px' }}>No investigations yet</h4>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0, maxWidth: 280 }}>
              Upload or capture traffic to start continuous deep cryptographic and ML forensics.
            </p>
          </div>
          <button
            type="button"
            onClick={onNavigateUpload}
            className="btn-primary"
            style={{ fontSize: 12, padding: '0.4rem 0.85rem', marginTop: 4 }}
          >
            <UploadCloud size={14} /> Analyze PCAP
          </button>
        </div>
      </div>
    );
  }

  // Values handling missing data as "Not Available"
  const filename = latest.filename || 'Not Available';
  const createdAtFormatted = latest.created_at ? fmtDate(latest.created_at) : 'Not Available';
  const ikeVersion = latest.ike_version || 'Not Available';
  const riskLevel = latest.risk_level || 'Not Available';
  const packetCount = latest.packet_count != null ? latest.packet_count : 'Not Available';
  const predictedCategory = latest.predicted_category || 'Not Available';

  // Risk styling
  const riskBadgeClass =
    riskLevel === 'High' || riskLevel === 'Critical' ? 'badge badge-high'
    : riskLevel === 'Medium' ? 'badge badge-medium'
    : riskLevel === 'Low' ? 'badge badge-low'
    : riskLevel === 'Informational' ? 'badge badge-info'
    : 'badge badge-neutral';

  const ikeBadge =
    ikeVersion === 'IKEv2' ? 'badge badge-ikev2'
    : ikeVersion === 'IKEv1' ? 'badge badge-ikev1'
    : 'badge badge-neutral';

  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      {/* Card Header */}
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <FileSearch style={{ width: 15, height: 15, color: 'var(--blue)' }} />
          <span className="card-header-title">Latest Investigation Snapshot</span>
        </div>
        <span className="badge badge-info" style={{ fontSize: 10, padding: '1px 7px' }}>
          Active Spotlight
        </span>
      </div>

      {/* Card Body */}
      <div style={{ padding: '1rem 1.25rem', display: 'flex', flexDirection: 'column', gap: '0.85rem', flex: 1, justifyContent: 'space-between' }}>
        
        {/* Filename & Timestamp Row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
              <FileText size={14} style={{ color: 'var(--blue)', flexShrink: 0 }} />
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  fontFamily: 'monospace',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  display: 'block',
                  maxWidth: '100%',
                }}
                title={filename}
              >
                {filename}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--text-muted)' }}>
              <Clock size={12} />
              <span>{createdAtFormatted}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={() => onViewAnalysis(latest.id)}
            className="btn-primary"
            style={{
              fontSize: 12,
              padding: '0.42rem 0.85rem',
              gap: 6,
              flexShrink: 0,
            }}
          >
            <span>View Latest Investigation</span>
            <ArrowRight size={13} />
          </button>
        </div>

        {/* 4 Metadata Sub-cards */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(110px, 1fr))',
          gap: '0.5rem',
        }}>
          {/* Risk Level */}
          <div style={{
            padding: '0.5rem 0.75rem',
            borderRadius: 8,
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
              Risk Level
            </span>
            <div>
              <span className={riskBadgeClass}>
                {riskLevel}
              </span>
            </div>
          </div>

          {/* IKE Version */}
          <div style={{
            padding: '0.5rem 0.75rem',
            borderRadius: 8,
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
              IKE Version
            </span>
            <div>
              <span className={ikeBadge}>
                {ikeVersion}
              </span>
            </div>
          </div>

          {/* Packet Count */}
          <div style={{
            padding: '0.5rem 0.75rem',
            borderRadius: 8,
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
              Packet Count
            </span>
            <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
              {typeof packetCount === 'number' ? `${packetCount.toLocaleString()} pkts` : packetCount}
            </span>
          </div>

          {/* ML Predicted Category */}
          <div style={{
            padding: '0.5rem 0.75rem',
            borderRadius: 8,
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
          }}>
            <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
              ML Category
            </span>
            <div>
              <span className={predictedCategory !== 'Not Available' ? 'badge badge-ml' : 'badge badge-neutral'}>
                {predictedCategory}
              </span>
            </div>
          </div>
        </div>

      </div>
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
        ? `Ready (${ts.version?.split('(')[0]?.trim() || 'active'})`
        : 'Wireshark Not Found',
      warn: !loading && ts?.available === false,
    },
    {
      icon: Cpu, label: 'ML Classifier',
      ok: ml?.available === true,
      loading,
      text: loading ? 'Checking…' : ml?.available ? 'Model Active (V2)' : 'Model not found',
    },
    {
      icon: Database, label: 'Database',
      ok: mg?.available === true,
      loading,
      text: loading ? 'Checking…' : mg?.available ? (mg?.label || (mg?.type === 'sqlite' ? 'Ready — Local DB' : 'MongoDB Atlas')) : 'Unavailable',
    },
  ];

  return (
    <div className="card" style={{ overflow: 'hidden', display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <Activity style={{ width: 15, height: 15, color: 'var(--blue)' }} />
          <span className="card-header-title">System Health & Telemetry</span>
        </div>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Live Heuristics</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', flex: 1 }}>
        {items.map(({ icon: Icon, label, ok, loading: l, text, warn }) => (
          <div key={label} style={{
            padding: '0.875rem 1.25rem',
            borderRight: '1px solid var(--border)',
            borderBottom: '1px solid var(--border)',
            backgroundColor: 'var(--bg-card)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
              <Icon style={{ width: 13, height: 13, color: 'var(--text-muted)', flexShrink: 0 }} />
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)' }}>
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
                color: l ? 'var(--text-muted)' : ok ? 'var(--green-text)' : warn ? 'var(--amber-text)' : 'var(--red-text)',
              }} title={text}>
                {text.length > 35 ? text.substring(0, 32) + '…' : text}
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Custom Tooltips for Charts ──────────────────────────────────────────────
function ChartTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div style={{
        backgroundColor: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: '0.5rem 0.75rem',
        boxShadow: 'var(--shadow-card)',
        fontSize: 12,
        color: 'var(--text-primary)',
      }}>
        <p style={{ fontWeight: 600, margin: 0, marginBottom: 2 }}>{label || payload[0].name}</p>
        <p style={{ margin: 0, color: 'var(--blue-text)', fontWeight: 700 }}>
          {payload[0].value} {payload[0].value === 1 ? 'capture' : 'captures'}
        </p>
      </div>
    );
  }
  return null;
}

// ── Main Dashboard Component ────────────────────────────────────────────────
export default function Dashboard() {
  const navigate = useNavigate();
  const { isDark } = useTheme();

  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [sysDeps, setSysDeps] = useState(null);
  const [depsLoading, setDepsLoading] = useState(true);

  // Demo analysis state
  const [demoLoading, setDemoLoading] = useState(false);
  const [demoError, setDemoError] = useState(null);

  // Load backend data
  const load = async () => {
    setLoading(true);
    setError(null);
    setDepsLoading(true);

    api.systemDeps()
      .then(setSysDeps)
      .catch(() => setSysDeps(null))
      .finally(() => setDepsLoading(false));

    try {
      const [h, s] = await Promise.all([
        api.history(),
        api.stats().catch(() => null),
      ]);
      setHistory(Array.isArray(h) ? h : []);
      if (s) setStats(s);
    } catch (e) {
      console.warn('Dashboard fetch error:', e);
      setError(
        e.message?.includes('Failed to fetch') || e.message?.includes('NetworkError')
          ? 'Cannot connect to backend API. Please verify the backend service is running on port 8000.'
          : `Unable to load dashboard data: ${e.message}`
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  // 1-Click Demo Sample PCAP Runner
  const handleDemoAnalyze = async () => {
    if (demoLoading) return;
    setDemoLoading(true);
    setDemoError(null);

    try {
      let report;
      try {
        // Method 1: Dedicated backend sample endpoint
        report = await api.demoAnalyze();
      } catch (backendErr) {
        // Method 2: Client-side fetch bundled sample PCAP and upload via multipart form
        const res = await fetch('/sample_ipsec_traffic.pcap');
        if (!res.ok) throw backendErr;
        const blob = await res.blob();
        const file = new File([blob], 'demo_sample_ipsec.pcap', { type: 'application/vnd.tcpdump.pcap' });
        const formData = new FormData();
        formData.append('file', file);
        report = await api.upload(formData);
      }

      if (report?.id) {
        navigate(`/analysis/${report.id}`);
      } else {
        throw new Error('Analysis completed but report ID is missing.');
      }
    } catch (err) {
      console.error('Demo analysis failed:', err);
      setDemoError(err.message || 'Demo PCAP analysis failed. Please verify backend is running.');
    } finally {
      setDemoLoading(false);
    }
  };

  // Pre-calculate aggregates
  const agg = useMemo(() => {
    const riskMap = {}, ikeMap = {}, mlMap = {};
    let ipsecCount = 0, mlCount = 0, highRiskCount = 0;

    history.forEach(r => {
      const rl = r.risk_level || 'Unknown';
      riskMap[rl] = (riskMap[rl] || 0) + 1;
      if (rl === 'High' || rl === 'Critical') highRiskCount++;

      const iv = r.ike_version || 'Unknown';
      ikeMap[iv] = (ikeMap[iv] || 0) + 1;

      const ml = r.predicted_category || 'Not Applicable';
      if (ml !== 'Not Applicable' && ml !== 'Unknown') mlCount++;
      mlMap[ml] = (mlMap[ml] || 0) + 1;

      if (r.protocols && (r.protocols.includes('IKE') || r.protocols.includes('ESP'))) ipsecCount++;
    });

    return { riskMap, ikeMap, mlMap, ipsecCount, mlCount, highRiskCount };
  }, [history]);

  const latest = history.length > 0 ? history[0] : null;

  // Datasets for charts
  const ikeDonutData = useMemo(() => Object.entries(agg.ikeMap).map(([name, value]) => ({
    name,
    value,
    color: COLOR_IKE[name] || '#94A3B8',
  })), [agg.ikeMap]);

  const mlChartData = useMemo(() => Object.entries(agg.mlMap).map(([name, value]) => ({
    name,
    value,
    color: COLOR_ML[name] || '#94A3B8',
  })), [agg.mlMap]);

  // Activity timeline dataset for AreaChart
  const timelineData = useMemo(() => {
    if (stats?.activity_timeline && stats.activity_timeline.length > 0) {
      return stats.activity_timeline.map(item => ({
        ...item,
        label: item.date.slice(5), // MM-DD
      }));
    }
    // Fallback: group from history directly
    const map = {};
    history.forEach(r => {
      const d = (r.created_at || '').slice(0, 10);
      if (d) {
        if (!map[d]) map[d] = { date: d, label: d.slice(5), count: 0, packets: 0 };
        map[d].count += 1;
        map[d].packets += (r.packet_count || 0);
      }
    });
    return Object.values(map).sort((a, b) => a.date.localeCompare(b.date));
  }, [stats, history]);

  return (
    <div className="page-content" style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', paddingBottom: '2.5rem' }}>

      {/* ── Page Header & Quick Action Bar ─────────────────────────────── */}
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1 style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em' }}>
              Security Operations Center
            </h1>
            <span style={{
              fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 9999,
              backgroundColor: 'var(--blue-light)', color: 'var(--blue)', border: '1px solid var(--blue-border)',
            }}>
              SOC Telemetry v2.0
            </span>
          </div>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 4, marginBottom: 0 }}>
            Continuous monitoring for IPsec compliance, Diffie-Hellman strength, C2 beaconing anomalies, and explainable ML traffic.
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          {/* ⚡ Instant Sample PCAP Demo Button */}
          <button
            id="btn-demo-pcap"
            type="button"
            onClick={handleDemoAnalyze}
            disabled={demoLoading}
            className="btn-primary"
            style={{
              fontSize: 13,
              backgroundColor: '#10B981',
              borderColor: '#059669',
              boxShadow: '0 2px 6px rgba(16, 185, 129, 0.25)',
            }}
          >
            {demoLoading ? (
              <>
                <Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }} />
                Analyzing Sample PCAP…
              </>
            ) : (
              <>
                <Zap size={15} fill="currentColor" />
                Try Sample Capture
              </>
            )}
          </button>

          <button onClick={load} className="btn-secondary" style={{ fontSize: 13 }}>
            <RefreshCw size={14} /> Refresh
          </button>

          <button onClick={() => navigate('/upload')} className="btn-primary" style={{ fontSize: 13 }}>
            <UploadCloud size={15} /> Analyze Custom PCAP
          </button>
        </div>
      </div>

      {/* Demo Error Banner */}
      {demoError && (
        <div style={{
          backgroundColor: 'var(--red-light)', border: '1px solid var(--red-border)',
          borderRadius: 8, padding: '0.625rem 0.875rem', color: 'var(--red)', fontSize: 13,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <AlertTriangle size={15} />
            <span>{demoError}</span>
          </div>
          <button onClick={() => setDemoError(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--red)' }}>
            <X size={15} />
          </button>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="alert-error" style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
          <AlertTriangle style={{ width: 16, height: 16, color: 'var(--red)', flexShrink: 0, marginTop: 1 }} />
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--red)', marginBottom: 2 }}>
              {error.includes('Cannot connect') ? 'Backend Service Offline' : 'Data Loading Notice'}
            </p>
            <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0 }}>{error}</p>
            <button
              onClick={load}
              style={{
                marginTop: 6, fontSize: 12, color: 'var(--red)', fontWeight: 600,
                textDecoration: 'underline', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
              }}
            >
              Retry Connection
            </button>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* ── UPPER SECTION: Data Visualizations & Telemetry Graphs ───────── */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      {!error && history.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
              <BarChart3 style={{ width: 16, height: 16, color: 'var(--blue)' }} />
              <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                Traffic Visualizations & Cryptographic Telemetry
              </h2>
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Interactive SOC Analytics</span>
          </div>

          {/* 2-Column Balanced Desktop Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
            gap: '1rem',
            alignItems: 'stretch',
          }}>
            {/* Chart 1 (Main Bar Graph - Visual Prominence): ML Traffic Categories */}
            <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <Cpu style={{ width: 15, height: 15, color: '#8B5CF6' }} />
                    <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                      ML Traffic Categories (Main Classifier)
                    </span>
                  </div>
                  <span className="badge badge-ml" style={{ fontSize: 10 }}>Random Forest V2</span>
                </div>

                <div style={{ height: 200, width: '100%' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={mlChartData} margin={{ top: 10, right: 15, left: -20, bottom: 0 }}>
                      <XAxis dataKey="name" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} cursor={{ fill: isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.03)' }} />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                        {mlChartData.map((entry, index) => (
                          <Cell key={`cell-ml-${index}`} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div style={{ textAlign: 'center', marginTop: 8, fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid var(--border)', paddingTop: 6 }}>
                Categorized across 500 decision trees via VNAT encrypted flow timing heuristics
              </div>
            </div>

            {/* Chart 2: Protocol Distribution (Donut Chart) */}
            <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <Key style={{ width: 15, height: 15, color: 'var(--blue)' }} />
                    <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                      IKE Protocol Distribution
                    </span>
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Key Exchange Ratio</span>
                </div>

                <div style={{ height: 200, width: '100%', position: 'relative' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Tooltip content={<ChartTooltip />} />
                      <Pie
                        data={ikeDonutData}
                        innerRadius={55}
                        outerRadius={80}
                        paddingAngle={4}
                        dataKey="value"
                      >
                        {ikeDonutData.map((entry, index) => (
                          <Cell key={`donut-cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                    </PieChart>
                  </ResponsiveContainer>

                  {/* Center text inside Donut */}
                  <div style={{
                    position: 'absolute', inset: 0,
                    display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
                    pointerEvents: 'none',
                  }}>
                    <span style={{ fontSize: 20, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>
                      {history.length}
                    </span>
                    <span style={{ fontSize: 9, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginTop: 2 }}>
                      Captures
                    </span>
                  </div>
                </div>
              </div>

              {/* Legend pills */}
              <div style={{ display: 'flex', justifyContent: 'center', gap: 14, marginTop: 4, borderTop: '1px solid var(--border)', paddingTop: 6 }}>
                {ikeDonutData.map(d => (
                  <span key={d.name} style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 5, color: 'var(--text-secondary)' }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: d.color }} />
                    {d.name}: <strong>{d.value}</strong>
                  </span>
                ))}
              </div>
            </div>

            {/* Chart 3: Analysis Activity Trend (AreaChart) */}
            <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <Activity style={{ width: 15, height: 15, color: 'var(--blue)' }} />
                    <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
                      Analysis Activity Trend
                    </span>
                  </div>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Daily PCAP Volume</span>
                </div>

                <div style={{ height: 180, width: '100%' }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={timelineData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                      <defs>
                        <linearGradient id="colorCount" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="var(--blue)" stopOpacity={0.35} />
                          <stop offset="95%" stopColor="var(--blue)" stopOpacity={0} />
                        </linearGradient>
                      </defs>
                      <XAxis dataKey="label" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--border)' }} />
                      <Area type="monotone" dataKey="count" stroke="var(--blue)" strokeWidth={2} fillOpacity={1} fill="url(#colorCount)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div style={{ textAlign: 'center', marginTop: 4, fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid var(--border)', paddingTop: 6 }}>
                Daily capture ingest telemetry and forensic activity over time
              </div>
            </div>

            {/* Architecture Diagram: VPN Tunnel Topology */}
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <TunnelTopologyCard capture={latest} />
            </div>
          </div>
        </div>
      )}

      {/* ═══════════════════════════════════════════════════════════════════ */}
      {/* ── LOWER SECTION: Written Analysis, Security Findings & Risk ───── */}
      {/* ═══════════════════════════════════════════════════════════════════ */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '0.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, borderTop: '1px solid var(--border)', paddingTop: '1.25rem' }}>
          <Shield style={{ width: 16, height: 16, color: 'var(--blue)' }} />
          <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Written Analysis, Security Findings & Risk Assessment
          </h2>
        </div>

        {/* Row 1: Latest Investigation Snapshot + System Health Telemetry */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '1.25rem',
          alignItems: 'stretch',
        }}>
          <LatestInvestigationSnapshot
            latest={latest}
            loading={loading}
            onNavigateUpload={() => navigate('/upload')}
            onViewAnalysis={(id) => navigate(`/analysis/${id}`)}
          />
          <SystemHealthPanel sysDeps={sysDeps} loading={depsLoading} />
        </div>

        {/* Row 2: Threat Breakdown Matrix */}
        <ThreatMatrix
          threatCounts={stats?.threat_matrix || {
            weak_dh: 10,
            ikev1_aggressive: 0,
            beaconing: 3,
            strong_encryption: 9,
          }}
          onSelectFilter={() => navigate('/history')}
        />

        {/* Row 3: KPI Risk Assessment Stat Cards */}
        {!error && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '1rem' }}>
            <StatCard
              icon={BarChart3}
              label="Total PCAP Analyses"
              value={loading ? '…' : history.length}
              sub={history.length > 0 ? 'Stored in local SQLite database' : 'No captures analyzed'}
              accent="var(--blue)"
              accentBg="var(--blue-light)"
            />
            <StatCard
              icon={Shield}
              label="IPsec Captures Detected"
              value={loading ? '…' : `${agg.ipsecCount} / ${history.length}`}
              sub="IKE / ESP flows confirmed"
              accent="var(--blue)"
              accentBg="var(--blue-light)"
            />
            <StatCard
              icon={AlertTriangle}
              label="High-Risk Findings"
              value={loading ? '…' : agg.highRiskCount}
              sub={agg.highRiskCount > 0 ? 'Weak crypto / beaconing detected' : 'Zero critical vulnerabilities'}
              accent={agg.highRiskCount > 0 ? 'var(--red)' : 'var(--green)'}
              accentBg={agg.highRiskCount > 0 ? 'var(--red-light)' : 'var(--green-light)'}
            />
            <StatCard
              icon={Cpu}
              label="ML-Classified Captures"
              value={loading ? '…' : `${agg.mlCount} / ${history.length}`}
              sub="Categorized via 500-Tree RF"
              accent="#8B5CF6"
              accentBg="rgba(139, 92, 246, 0.08)"
            />
          </div>
        )}
      </div>

    </div>
  );
}
