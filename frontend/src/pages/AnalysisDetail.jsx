import { useState, useEffect, useMemo } from 'react';
import { useParams, useLocation, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Download, Shield, Activity, Lock, Key, Wifi,
  AlertTriangle, CheckCircle, XCircle, Info, Cpu, FlaskConical,
  SkipForward, ListChecks, AlertCircle, Layers, RefreshCw,
  Search, ChevronDown, ChevronRight, BarChart3, Binary, Wrench, FileSearch, Radio, Sparkles, HelpCircle, FileText,
  Clock, ArrowUpDown, Globe, ExternalLink
} from 'lucide-react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer
} from 'recharts';
import { api } from '../lib/api';
import { fmtDate, riskColor, sevColor, strengthOf } from '../lib/utils';

// ── Severity icon map ──────────────────────────────────────────────────────
const SEV_ICON = {
  Critical:      <XCircle       style={{ width: 15, height: 15, color: '#B91C1C', flexShrink: 0 }} />,
  High:          <AlertTriangle style={{ width: 15, height: 15, color: '#DC2626', flexShrink: 0 }} />,
  Medium:        <AlertTriangle style={{ width: 15, height: 15, color: '#D97706', flexShrink: 0 }} />,
  Low:           <Info          style={{ width: 15, height: 15, color: '#2563EB', flexShrink: 0 }} />,
  Informational: <CheckCircle   style={{ width: 15, height: 15, color: '#16A34A', flexShrink: 0 }} />,
};

// ── MetricCard ─────────────────────────────────────────────────────────────
function MetricCard({ icon: Icon, label, value }) {
  const empty = !value || value === 'Not Extracted' || value === 'Unknown' || value === 'Not Available';
  return (
    <div className="card-surface" style={{ padding: '0.875rem 1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 6 }}>
        <Icon style={{ width: 11, height: 11, color: '#94A3B8' }} />
        <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94A3B8' }}>{label}</span>
      </div>
      <p style={{ fontSize: 13, fontWeight: 600, color: empty ? '#94A3B8' : 'var(--text-primary)', fontStyle: empty ? 'italic' : 'normal' }}>
        {empty ? 'Not Extracted' : value}
      </p>
    </div>
  );
}

// ── CryptoRow ──────────────────────────────────────────────────────────────
function CryptoRow({ label, value }) {
  const empty    = !value || value === 'Not Extracted' || value === 'Unknown';
  const strength = empty ? null : strengthOf(value);
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0.75rem 0', borderBottom: '1px solid #F1F5F9' }}>
      <span style={{ fontSize: 13, color: '#64748B', flexShrink: 0 }}>{label}</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: '1rem' }}>
        <span style={{ fontSize: 13, fontWeight: 500, textAlign: 'right', maxWidth: 240, color: empty ? '#94A3B8' : 'var(--text-primary)', fontStyle: empty ? 'italic' : 'normal' }}>
          {empty ? 'Not Extracted' : value}
        </span>
        {strength && <span className={strength.cls}>{strength.label}</span>}
        {empty && <span className="badge badge-neutral">Not Extracted</span>}
      </div>
    </div>
  );
}

// ── Evidence-Based FindingCard ─────────────────────────────────────────────
function FindingCard({ f }) {
  const sc = sevColor(f.severity);

  // Map severity to border-left accent
  const accentColor =
    f.severity === 'High' || f.severity === 'Critical' ? '#DC2626' :
    f.severity === 'Medium' ? '#D97706' :
    f.severity === 'Low' ? '#2563EB' : '#16A34A';

  return (
    <div style={{
      borderRadius: 10, border: '1px solid #E2E8F0',
      borderLeft: `3px solid ${accentColor}`,
      backgroundColor: '#FFFFFF', padding: '1.125rem',
      display: 'flex', flexDirection: 'column', gap: '0.75rem',
    }}>
      {/* Title & severity badge */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {SEV_ICON[f.severity] || SEV_ICON.Informational}
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{f.title}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          {f.risk_contribution > 0 && (
            <span style={{ fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 9999, backgroundColor: '#FEF2F2', color: '#B91C1C', border: '1px solid #FECACA' }}>
              +{f.risk_contribution} risk
            </span>
          )}
          <span className={`badge ${sc}`}>{f.severity}</span>
        </div>
      </div>

      {/* Short Explanation */}
      <div style={{ fontSize: 12, color: '#475569', lineHeight: 1.6 }}>
        {f.description}
      </div>

      {/* Actual PCAP Evidence Box */}
      {f.evidence && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 8,
          padding: '0.625rem 0.875rem', borderRadius: 6,
          backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0',
        }}>
          <FileSearch style={{ width: 14, height: 14, color: '#2563EB', flexShrink: 0, marginTop: 2 }} />
          <div style={{ fontSize: 11, lineHeight: 1.55 }}>
            <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>PCAP Evidence: </span>
            <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{f.evidence}</span>
          </div>
        </div>
      )}

      {/* Remediation Recommendation Box */}
      {f.recommendation && (
        <div style={{
          display: 'flex', alignItems: 'flex-start', gap: 8,
          padding: '0.625rem 0.875rem', borderRadius: 6,
          backgroundColor: '#F0FDF4', border: '1px solid #BBF7D0',
        }}>
          <Wrench style={{ width: 14, height: 14, color: '#15803D', flexShrink: 0, marginTop: 2 }} />
          <div style={{ fontSize: 11, lineHeight: 1.55, color: '#166534' }}>
            <span style={{ fontWeight: 600 }}>Remediation: </span>
            <span>{f.recommendation}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Rule Audit ─────────────────────────────────────────────────────────────
function RuleAudit({ evaluated = [], skipped = [] }) {
  if (evaluated.length === 0 && skipped.length === 0) return null;
  return (
    <div id="rule-audit-trail" style={{ marginTop: '1.25rem', borderRadius: 10, border: '1px solid #E2E8F0', backgroundColor: '#FFFFFF', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.625rem 1rem', borderBottom: '1px solid #E2E8F0', backgroundColor: '#F8FAFC' }}>
        <ListChecks style={{ width: 12, height: 12, color: '#94A3B8' }} />
        <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8' }}>Rule Audit Trail</span>
      </div>
      <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
        <thead>
          <tr style={{ borderBottom: '1px solid #F1F5F9' }}>
            {['Rule', 'Observed Value', 'Status'].map(h => (
              <th key={h} style={{ textAlign: 'left', padding: '0.5rem 0.875rem', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: '#94A3B8' }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {evaluated.map((r, i) => {
            const rawStatus = r.status || 'UNKNOWN';
            const isPass = rawStatus === 'PASS';
            const isFail = rawStatus === 'FAIL';
            const displayStatus = isPass ? 'RULE PASSED' : isFail ? 'WEAKNESS DETECTED' : rawStatus;

            let color = '#D97706';
            let icon = <AlertCircle style={{ width: 11, height: 11 }} />;
            if (isPass) {
              color = '#15803D';
              icon = <CheckCircle style={{ width: 11, height: 11 }} />;
            } else if (isFail) {
              color = '#B91C1C';
              icon = <XCircle style={{ width: 11, height: 11 }} />;
            }

            return (
              <tr key={`ev-${i}`} style={{ borderBottom: '1px solid #F8FAFC' }}>
                <td style={{ padding: '0.625rem 0.875rem', fontWeight: 500, color: 'var(--text-primary)' }}>{r.rule}</td>
                <td style={{ padding: '0.625rem 0.875rem', color: '#475569', fontFamily: 'monospace' }}>{r.observed_value || '—'}</td>
                <td style={{ padding: '0.625rem 0.875rem' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontWeight: 600, fontSize: 11, color }}>
                    {icon}
                    {displayStatus}
                  </span>
                </td>
              </tr>
            );
          })}
          {skipped.map((r, i) => (
            <tr key={`sk-${i}`} style={{ borderBottom: '1px solid #F8FAFC', backgroundColor: '#FAFBFC' }}>
              <td style={{ padding: '0.625rem 0.875rem', color: '#94A3B8' }}>{r.rule}</td>
              <td style={{ padding: '0.625rem 0.875rem', color: '#CBD5E1', fontStyle: 'italic' }}>Not Extracted</td>
              <td style={{ padding: '0.625rem 0.875rem' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontWeight: 600, fontSize: 11, color: '#D97706' }}>
                  <SkipForward style={{ width: 11, height: 11 }} /> SKIPPED
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {skipped.length > 0 && (
        <div style={{ padding: '0.5rem 0.875rem', borderTop: '1px solid #F1F5F9', fontSize: 11, color: '#94A3B8', backgroundColor: '#FAFBFC' }}>
          {skipped[0]?.reason}
        </div>
      )}
    </div>
  );
}

// ── Analysis Coverage Summary ──────────────────────────────────────────────
function AnalysisCoverageSummary({ evaluated = [], skipped = [] }) {
  if (evaluated.length === 0 && skipped.length === 0) return null;

  const passCount  = evaluated.filter(r => r.status === 'PASS').length;
  const failCount  = evaluated.filter(r => r.status === 'FAIL').length;
  const otherCount = evaluated.filter(r => r.status !== 'PASS' && r.status !== 'FAIL').length;
  const skipCount  = skipped.length;
  const totalRan   = evaluated.length;

  // Scroll to the Rule Audit Trail anchor below
  const scrollToAudit = () => {
    const el = document.getElementById('rule-audit-trail');
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div style={{
      marginTop: '1rem',
      borderRadius: 10,
      border: '1px solid #E2E8F0',
      backgroundColor: '#FFFFFF',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0.625rem 1rem',
        borderBottom: '1px solid #E2E8F0',
        backgroundColor: '#F8FAFC',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <ListChecks style={{ width: 12, height: 12, color: '#94A3B8' }} />
          <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8' }}>
            Analysis Coverage Summary
          </span>
        </div>
        <button
          onClick={scrollToAudit}
          style={{
            fontSize: 10, fontWeight: 600, color: '#2563EB',
            background: 'none', border: 'none', cursor: 'pointer',
            padding: '2px 6px', borderRadius: 4,
          }}
          title="Jump to full Rule Audit Trail"
        >
          View Full Audit ↓
        </button>
      </div>

      {/* Count badges */}
      <div style={{ display: 'flex', gap: '0.75rem', padding: '0.75rem 1rem', flexWrap: 'wrap', borderBottom: '1px solid #F1F5F9' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.35rem 0.75rem', borderRadius: 6, backgroundColor: '#F0FDF4', border: '1px solid #BBF7D0' }}>
          <CheckCircle style={{ width: 12, height: 12, color: '#15803D' }} />
          <span style={{ fontSize: 12, fontWeight: 700, color: '#15803D' }}>{passCount}</span>
          <span style={{ fontSize: 11, color: '#166534' }}>Rule Passed</span>
        </div>
        {failCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.35rem 0.75rem', borderRadius: 6, backgroundColor: '#FEF2F2', border: '1px solid #FECACA' }}>
            <XCircle style={{ width: 12, height: 12, color: '#B91C1C' }} />
            <span style={{ fontSize: 12, fontWeight: 700, color: '#B91C1C' }}>{failCount}</span>
            <span style={{ fontSize: 11, color: '#991B1B' }}>Weakness Detected</span>
          </div>
        )}
        {otherCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.35rem 0.75rem', borderRadius: 6, backgroundColor: '#FFFBEB', border: '1px solid #FDE68A' }}>
            <AlertCircle style={{ width: 12, height: 12, color: '#D97706' }} />
            <span style={{ fontSize: 12, fontWeight: 700, color: '#D97706' }}>{otherCount}</span>
            <span style={{ fontSize: 11, color: '#92400E' }}>Other</span>
          </div>
        )}
        {skipCount > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.35rem 0.75rem', borderRadius: 6, backgroundColor: '#FFFBEB', border: '1px solid #FDE68A' }}>
            <SkipForward style={{ width: 12, height: 12, color: '#D97706' }} />
            <span style={{ fontSize: 12, fontWeight: 700, color: '#D97706' }}>{skipCount}</span>
            <span style={{ fontSize: 11, color: '#92400E' }}>Skipped</span>
          </div>
        )}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.35rem 0.75rem', borderRadius: 6, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
          <Info style={{ width: 12, height: 12, color: '#64748B' }} />
          <span style={{ fontSize: 11, color: '#64748B' }}>{totalRan} of {totalRan + skipCount} rules ran</span>
        </div>
      </div>

      {/* Skipped parameters detail */}
      {skipCount > 0 && (
        <div style={{ padding: '0.75rem 1rem' }}>
          <p style={{ fontSize: 11, fontWeight: 600, color: '#475569', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Parameters Not Verifiable from This Capture
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {skipped.map((r, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'flex-start', gap: 8,
                padding: '0.5rem 0.75rem', borderRadius: 6,
                backgroundColor: '#FFFBEB', border: '1px solid #FDE68A',
              }}>
                <SkipForward style={{ width: 11, height: 11, color: '#D97706', flexShrink: 0, marginTop: 2 }} />
                <div style={{ flex: 1 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: '#92400E' }}>{r.rule}</span>
                  {r.reason && (
                    <p style={{ fontSize: 11, color: '#B45309', lineHeight: 1.55, marginTop: 2 }}>
                      {r.reason}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
          <p style={{ fontSize: 11, color: '#94A3B8', marginTop: '0.625rem', lineHeight: 1.6 }}>
            Skipped checks are neither passed nor failed — the required parameters were not observable
            in this packet capture. Skipped rules do not contribute to the risk score.
          </p>
        </div>
      )}
    </div>
  );
}

// ── Packet-Size Distribution Chart ─────────────────────────────────────────
function PacketSizeDistribution({ distribution = [], stats = {} }) {
  if (!distribution || distribution.length === 0) {
    return (
      <div style={{ padding: '1rem', textAlign: 'center', color: '#94A3B8', fontSize: 12, backgroundColor: '#F8FAFC', borderRadius: 8 }}>
        No packet size data available for this capture.
      </div>
    );
  }

  const maxPct = Math.max(...distribution.map(d => d.percentage || 0), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Quick summary badges */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
        <div style={{ padding: '0.5rem 0.875rem', borderRadius: 6, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', flex: 1 }}>
          <p style={{ fontSize: 10, fontWeight: 600, color: '#94A3B8', textTransform: 'uppercase' }}>Min Size</p>
          <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{stats?.min_size ?? 0} B</p>
        </div>
        <div style={{ padding: '0.5rem 0.875rem', borderRadius: 6, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', flex: 1 }}>
          <p style={{ fontSize: 10, fontWeight: 600, color: '#94A3B8', textTransform: 'uppercase' }}>Average Size</p>
          <p style={{ fontSize: 14, fontWeight: 700, color: '#2563EB' }}>{stats?.avg_size ?? 0} B</p>
        </div>
        <div style={{ padding: '0.5rem 0.875rem', borderRadius: 6, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', flex: 1 }}>
          <p style={{ fontSize: 10, fontWeight: 600, color: '#94A3B8', textTransform: 'uppercase' }}>Max Size</p>
          <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{stats?.max_size ?? 0} B</p>
        </div>
      </div>

      {/* Horizontal Distribution Bars */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
        {distribution.map(d => {
          const barWidth = d.percentage > 0 ? Math.max((d.percentage / maxPct) * 100, 2) : 0;
          return (
            <div key={d.bin} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{d.bin}</span>
                <span style={{ color: '#64748B' }}>
                  {d.count} pkts ({d.percentage}%)
                </span>
              </div>
              <div style={{
                height: 8, width: '100%', backgroundColor: '#E2E8F0',
                borderRadius: 4, overflow: 'hidden', position: 'relative',
              }}>
                <div style={{
                  height: '100%', width: `${barWidth}%`,
                  backgroundColor: d.percentage > 30 ? '#2563EB' : d.percentage > 10 ? '#3B82F6' : '#93C5FD',
                  borderRadius: 4, transition: 'width 0.4s ease',
                }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── ML Section ─────────────────────────────────────────────────────────────
const ML_COLORS = {
  C2: '#DC2626',
  CHAT: '#2563EB',
  FILE_TRANSFER: '#16A34A',
  STREAMING: '#D97706',
  VOIP: '#7C3AED',
  'Inconclusive (Short Capture)': '#64748B',
  'Unclassified / Mixed Flow': '#64748B',
  'Unknown': '#64748B',
};

// Confidence thresholds — defined once, clearly, here.
// LOW_CONF_THRESHOLD : predictions below this percentage are flagged as low-confidence
// AMBIG_SPREAD_THRESHOLD : if (1st class score - 2nd class score) < this, flag as ambiguous
const LOW_CONF_THRESHOLD   = 50;   // %
const AMBIG_SPREAD_THRESHOLD = 15; // percentage points

function MLProbaTooltip({ active, payload }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div style={{
      padding: '6px 10px', borderRadius: 6, fontSize: 11,
      backgroundColor: '#FFFFFF', border: '1px solid #E2E8F0',
      boxShadow: '0 2px 6px rgba(15,23,42,0.08)',
    }}>
      <span style={{ fontWeight: 700, color: ML_COLORS[d.name] || 'var(--text-secondary)' }}>{d.name}</span>
      <span style={{ color: '#64748B', marginLeft: 8 }}>{d.value}%</span>
    </div>
  );
}

// ── Feature 1: Class Probability Card (Main Bar Graph) ────────────────────
function ClassProbabilityCard({ ml }) {
  if (!ml) return null;
  const { model_status, model_note, predicted_category: raw_pred, confidence_score,
          all_class_probabilities, dataset_note, raw_predicted_category } = ml;

  const confPct = confidence_score != null ? parseFloat((confidence_score * 100).toFixed(1)) : null;
  const probaArr = all_class_probabilities
    ? Object.entries(all_class_probabilities)
        .map(([name, value]) => ({ name, value: parseFloat((value * 100).toFixed(1)) }))
        .sort((a, b) => b.value - a.value)
    : [];

  const predicted_category = (raw_pred && raw_pred.includes('Inconclusive'))
    ? (raw_predicted_category || (probaArr.length > 0 ? probaArr[0].name : raw_pred))
    : (raw_pred || 'Unknown');

  const isLowConf   = confPct != null && confPct < LOW_CONF_THRESHOLD;
  const spread      = probaArr.length >= 2 ? probaArr[0].value - probaArr[1].value : null;
  const isAmbiguous = spread != null && spread < AMBIG_SPREAD_THRESHOLD;
  const isC2        = predicted_category === 'C2';

  return (
    <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <SectionHead icon={Cpu} title="ML Traffic Classification" action={
          <span className="badge badge-ml" style={{ fontSize: 10 }}>500-Tree RF</span>
        } />

        {model_status === 'not_applicable' ? (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', marginTop: '0.75rem' }}>
            <AlertCircle style={{ width: 15, height: 15, color: '#64748B', flexShrink: 0, marginTop: 1 }} />
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 2 }}>Classification Not Applicable</p>
              <p style={{ fontSize: 12, color: '#64748B', lineHeight: 1.6, margin: 0 }}>{model_note}</p>
            </div>
          </div>
        ) : model_status !== 'trained_model' ? (
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: '#FFFBEB', border: '1px solid #FDE68A', marginTop: '0.75rem' }}>
            <AlertTriangle style={{ width: 15, height: 15, color: '#D97706', flexShrink: 0, marginTop: 1 }} />
            <div>
              <p style={{ fontSize: 13, fontWeight: 600, color: '#92400E', marginBottom: 2 }}>Model Notice</p>
              <p style={{ fontSize: 12, color: '#B45309', lineHeight: 1.6, margin: 0 }}>{model_note}</p>
            </div>
          </div>
        ) : (
          <>
            {/* Active model notice */}
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '0.625rem 0.75rem', borderRadius: 8, backgroundColor: '#F5F3FF', border: '1px solid #DDD6FE', marginTop: '0.75rem', marginBottom: '0.75rem' }}>
              <FlaskConical style={{ width: 13, height: 13, color: '#7C3AED', flexShrink: 0, marginTop: 2 }} />
              <p style={{ fontSize: 11, color: '#6D28D9', lineHeight: 1.5, margin: 0 }}>
                <strong>Random Forest Active.</strong> {dataset_note || 'Trained on MIT Lincoln Laboratory VNAT dataset.'}
              </p>
            </div>

            {/* Prediction & Confidence Block */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
              <div style={{ padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', marginBottom: 4 }}>
                  Predicted Category
                </p>
                <p style={{ fontSize: '1.4rem', fontWeight: 800, color: ML_COLORS[predicted_category] || '#6D28D9', lineHeight: 1.1, margin: 0 }}>
                  {predicted_category}
                </p>
                <p style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, margin: '4px 0 0' }}>
                  Inferred from flow cadence
                </p>
              </div>

              <div style={{ padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4 }}>
                  <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', margin: 0 }}>
                    Confidence Score
                  </p>
                  <span title="Posterior class probability generated by the 500-tree Random Forest classifier." style={{ cursor: 'help' }}>
                    <HelpCircle size={11} style={{ color: 'var(--text-muted)' }} />
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
                  <span style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.1 }}>
                    {confPct != null ? `${confPct}%` : 'N/A'}
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>probability</span>
                </div>
                {confPct != null && (
                  <div style={{ height: 4, width: '100%', backgroundColor: 'var(--border)', borderRadius: 2, marginTop: 6, overflow: 'hidden' }}>
                    <div style={{
                      height: '100%', width: `${confPct}%`,
                      backgroundColor: confPct > 75 ? 'var(--green)' : confPct > LOW_CONF_THRESHOLD ? 'var(--blue)' : 'var(--amber)',
                      borderRadius: 2, transition: 'width 0.4s ease',
                    }} />
                  </div>
                )}
              </div>
            </div>

            {/* Caution banners if applicable */}
            {(isLowConf || isAmbiguous) && (
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '0.5rem 0.75rem', borderRadius: 6, backgroundColor: '#FFFBEB', border: '1px solid #FDE68A', marginBottom: '0.75rem' }}>
                <AlertTriangle style={{ width: 13, height: 13, color: '#D97706', flexShrink: 0, marginTop: 1 }} />
                <p style={{ fontSize: 11, color: '#B45309', lineHeight: 1.5, margin: 0 }}>
                  {isLowConf && `Confidence is ${confPct}% (below ${LOW_CONF_THRESHOLD}%). `}
                  {isAmbiguous && spread != null && `Top two classes differ by only ${spread.toFixed(1)} pp. `}
                  Classification should be treated as indicative.
                </p>
              </div>
            )}

            {isC2 && (
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '0.5rem 0.75rem', borderRadius: 6, backgroundColor: '#FEF2F2', border: '1px solid #FECACA', marginBottom: '0.75rem' }}>
                <Info style={{ width: 13, height: 13, color: '#B91C1C', flexShrink: 0, marginTop: 1 }} />
                <p style={{ fontSize: 11, color: '#991B1B', lineHeight: 1.5, margin: 0 }}>
                  <strong>C2 Classification:</strong> Behavioral profile matches VNAT C2 flow timings; does not confirm malicious traffic.
                </p>
              </div>
            )}

            {/* Main Bar Graph — Class Probability Breakdown */}
            {probaArr.length > 0 && (
              <div style={{ borderRadius: 8, border: '1px solid var(--border)', overflow: 'hidden', backgroundColor: 'var(--bg-card)' }}>
                <div style={{
                  padding: '0.5rem 0.75rem', fontSize: 10, fontWeight: 600,
                  textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)',
                  borderBottom: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)',
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                }}>
                  <span>Class Probability Breakdown (Main Visualizer)</span>
                  <span style={{ fontSize: 9, color: 'var(--blue)', fontWeight: 700 }}>5 Classes</span>
                </div>
                <div style={{ padding: '0.625rem 0.75rem 0.35rem' }}>
                  <ResponsiveContainer width="100%" height={probaArr.length * 28 + 12}>
                    <BarChart
                      data={probaArr}
                      layout="vertical"
                      margin={{ top: 0, right: 35, left: 75, bottom: 0 }}
                      barSize={11}
                    >
                      <XAxis
                        type="number"
                        domain={[0, 100]}
                        tickFormatter={v => `${v}%`}
                        tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                        axisLine={false}
                        tickLine={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="name"
                        tick={{ fontSize: 11, fontWeight: 600, fill: 'var(--text-primary)' }}
                        axisLine={false}
                        tickLine={false}
                        width={72}
                      />
                      <Tooltip content={<MLProbaTooltip />} cursor={{ fill: 'rgba(37,99,235,0.05)' }} />
                      <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                        {probaArr.map((d) => (
                          <Cell
                            key={d.name}
                            fill={d.name === predicted_category
                              ? ML_COLORS[d.name] || '#6D28D9'
                              : `${ML_COLORS[d.name] || '#94A3B8'}50`}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                  <p style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2, textAlign: 'right', margin: '2px 0 0' }}>
                    Highlighted bar = predicted category
                  </p>
                </div>
              </div>
            )}
          </>
        )}
      </div>

      <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5, borderLeft: '2px solid var(--blue)', paddingLeft: '0.6rem', margin: '0.75rem 0 0' }}>
        {model_note || 'Encrypted ESP traffic classified via statistical timing without payload decryption.'}
      </p>
    </div>
  );
}

// ── Feature 2: Packet-Size Distribution Card ──────────────────────────────
function PacketDistributionCard({ distribution = [], stats = {} }) {
  return (
    <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <SectionHead icon={BarChart3} title="Packet-Size Distribution" action={
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Actual PCAP Lengths</span>
        } />
        <div style={{ marginTop: '0.75rem' }}>
          <PacketSizeDistribution distribution={distribution} stats={stats} />
        </div>
      </div>
      <p style={{ fontSize: 11, color: 'var(--text-muted)', borderTop: '1px solid var(--border)', paddingTop: '0.5rem', margin: '0.75rem 0 0' }}>
        Audits packet frame size variance across outer IPsec ESP and control handshakes.
      </p>
    </div>
  );
}

// ── Feature 3: Explainable AI Decision Factors ────────────────────────────
function XaiCard({ ml }) {
  if (!ml || !ml.explainability || !ml.explainability.top_contributing_factors?.length) {
    return (
      <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'center', alignItems: 'center', textAlign: 'center' }}>
        <Sparkles style={{ width: 22, height: 22, color: 'var(--text-muted)', marginBottom: 8 }} />
        <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 4px' }}>Tree Attribution Not Available</p>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: 0 }}>Sufficient packet flow metrics required for decision path breakdown.</p>
      </div>
    );
  }

  const { predicted_category: raw_pred, raw_predicted_category } = ml;
  const predicted_category = raw_pred && raw_pred.includes('Inconclusive') ? (raw_predicted_category || raw_pred) : (raw_pred || 'traffic class');

  return (
    <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <SectionHead icon={Sparkles} title="Explainable AI (XAI) Decision Factors" action={
          <span className="badge badge-info" style={{ fontSize: 10 }}>Tree Path</span>
        } />

        {ml.explainability.summary && (
          <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0.75rem 0 0.625rem', fontWeight: 500 }}>
            {ml.explainability.summary}
          </p>
        )}

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {ml.explainability.top_contributing_factors.slice(0, 3).map((factor) => (
            <div
              key={factor.rank}
              style={{
                padding: '0.625rem 0.75rem',
                borderRadius: 8,
                backgroundColor: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                display: 'flex',
                flexDirection: 'column',
                gap: 4,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, minWidth: 0 }}>
                  <span style={{
                    width: 18, height: 18, borderRadius: '50%',
                    backgroundColor: 'var(--blue-light)', color: 'var(--blue)',
                    fontSize: 10, fontWeight: 700, display: 'inline-flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0
                  }}>
                    {factor.rank}
                  </span>
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {factor.feature_name}
                  </span>
                  <span style={{
                    fontSize: 10, fontWeight: 600, color: 'var(--green-text)',
                    backgroundColor: 'var(--green-light)', border: '1px solid var(--green-border)',
                    padding: '1px 5px', borderRadius: 4, fontFamily: 'monospace', flexShrink: 0,
                  }}>
                    {factor.observed_value}
                  </span>
                </div>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--blue)', flexShrink: 0 }}>
                  {factor.impact_percentage}%
                </span>
              </div>
              <div style={{ height: 3, width: '100%', backgroundColor: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${Math.min(100, factor.impact_percentage)}%`,
                  backgroundColor: 'var(--blue)',
                  borderRadius: 2,
                }} />
              </div>
              <p style={{ fontSize: 11, color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>
                {factor.reason}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '0.5rem', borderTop: '1px solid var(--border)', marginTop: '0.75rem' }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
          Attribution computes class probability shift across all 500 decision trees.
        </span>
        <span style={{ fontSize: 10, color: 'var(--blue)', fontWeight: 600 }}>
          Stronger driver toward {predicted_category}
        </span>
      </div>
    </div>
  );
}

// ── Beaconing & Anomaly Analysis Card ───────────────────────────────────────
function resolveBeaconing(beaconing, packets) {
  if (beaconing && beaconing.status === 'evaluated') return beaconing;
  if (!packets || packets.length < 5) return beaconing;

  const parsed = [];
  const sizes = [];
  for (const p of packets) {
    if (p.timestamp && typeof p.timestamp === 'string' && p.timestamp.includes('s')) {
      const match = p.timestamp.replace('+', '').replace('s', '').trim();
      const val = parseFloat(match);
      if (!isNaN(val)) {
        parsed.push(val);
        sizes.push(p.length || 0);
      }
    }
  }
  if (parsed.length < 5) return beaconing;

  const iats = [];
  for (let i = 1; i < parsed.length; i++) {
    const diff = parsed[i] - parsed[i - 1];
    if (diff > 1e-5) iats.push(diff);
  }
  if (iats.length < 4) return beaconing;

  const duration = Math.max(0, parsed[parsed.length - 1] - parsed[0]);
  const numIntervals = iats.length;

  const meanIat = iats.reduce((a, b) => a + b, 0) / iats.length;
  const variance = iats.reduce((a, b) => a + Math.pow(b - meanIat, 2), 0) / iats.length;
  const stdIat = Math.sqrt(variance);
  const cvIat = meanIat > 0 ? stdIat / meanIat : 99;

  const sortedIats = [...iats].sort((a, b) => a - b);
  const medianIat = sortedIats[Math.floor(sortedIats.length / 2)];

  const lower = 0.75 * medianIat;
  const upper = 1.25 * medianIat;
  const inCluster = iats.filter(x => x >= lower && x <= upper).length;
  const clusterRatio = inCluster / iats.length;

  const bursts = iats.filter(x => x < 0.05).length;
  const burstRatio = bursts / iats.length;

  // Confidence & Sample Size Scaling
  const intervalFactor = numIntervals < 6 ? 0.35 : numIntervals < 10 ? 0.50 : numIntervals < 15 ? 0.70 : numIntervals < 20 ? 0.85 : 1.0;
  const cyclesObserved = medianIat > 0 ? duration / medianIat : 0;
  const cycleFactor = cyclesObserved < 5 ? 0.40 : cyclesObserved < 10 ? 0.70 : cyclesObserved < 15 ? 0.85 : 1.0;
  const confidenceScore = parseFloat((intervalFactor * cycleFactor).toFixed(2));
  const confidenceLevel = confidenceScore >= 0.75 && numIntervals >= 12 ? 'HIGH' : confidenceScore >= 0.45 && numIntervals >= 8 ? 'MODERATE' : 'LOW';
  const isSmallSample = numIntervals < 10 || confidenceLevel === 'LOW';

  const timingReg = Math.max(0, Math.min(100, (1.0 - Math.min(cvIat, 1.5) / 1.5) * 100));
  let score = (timingReg / 100) * 45 + clusterRatio * 35;
  if (medianIat >= 0.5 && medianIat <= 120) score += 20;
  else if (medianIat >= 0.2) score += 12;
  else score += Math.max(0, 5 * (1 - burstRatio));

  if (burstRatio > 0.6) score *= (1 - (burstRatio - 0.5));

  const anomalyScore = isSmallSample
    ? parseFloat(Math.max(0, Math.min(45, score * Math.max(0.35, confidenceScore))).toFixed(1))
    : parseFloat(Math.max(0, Math.min(100, score * Math.max(0.70, confidenceScore))).toFixed(1));

  const isHigh = anomalyScore >= 68 && !isSmallSample;
  const isMed = (anomalyScore >= 40 && anomalyScore < 68) || (isSmallSample && timingReg >= 70);
  const insights = [];
  if (isHigh) {
    insights.push(`Observed persistent inter-arrival periodicity around ${medianIat.toFixed(2)}s with low jitter (CV = ${cvIat.toFixed(2)}) across ${numIntervals} intervals (${duration.toFixed(1)}s window).`);
    insights.push(`${Math.round(clusterRatio * 100)}% of packet intervals fall tightly within ±25% of median interval.`);
    insights.push('Periodic timing is a behavioral indicator, not definitive proof of malicious activity. Correlate with destination reputation and endpoint telemetry.');
  } else if (isMed) {
    insights.push(`Moderate timing regularity observed (CV = ${cvIat.toFixed(2)}, interval ~${medianIat.toFixed(2)}s, ${confidenceLevel} confidence).`);
    if (isSmallSample) {
      insights.push(`Small sample size observed (${numIntervals} intervals over ${duration.toFixed(1)}s). May correspond to automated synthetic tests or initial keep-alives rather than persistent C2.`);
    } else {
      insights.push('May correspond to routine background keep-alives, network synchronization, or jittered telemetry.');
    }
    insights.push('Periodic timing is a behavioral indicator, not definitive proof of compromise.');
  } else {
    insights.push(`High timing variance (CV = ${cvIat.toFixed(2)}) indicates sporadic, variable application traffic.`);
    if (burstRatio > 0.3) {
      insights.push(`${Math.round(burstRatio * 100)}% of packets arrived in rapid bursts (<50ms), typical of interactive sessions.`);
    }
  }

  return {
    status: 'evaluated',
    anomaly_score: anomalyScore,
    anomaly_level: isHigh ? 'HIGH' : isMed ? 'ELEVATED' : 'LOW',
    beacon_detected: isHigh,
    confidence_level: confidenceLevel,
    confidence_score: confidenceScore,
    sample_size_intervals: numIntervals,
    observation_duration_sec: parseFloat(duration.toFixed(3)),
    is_small_sample: isSmallSample,
    timing_regularity_pct: parseFloat(timingReg.toFixed(1)),
    estimated_interval_sec: parseFloat(medianIat.toFixed(3)),
    jitter_sec: parseFloat(stdIat.toFixed(3)),
    coefficient_of_variation: parseFloat(cvIat.toFixed(3)),
    total_intervals_analyzed: numIntervals,
    verdict: isHigh
      ? 'High Risk: Periodic Beaconing Detected (Behavioral C2 Indicator)'
      : isSmallSample && timingReg >= 70
      ? 'Notice: Regular Cadence in Small Sample (Low Confidence / Behavioral Indicator)'
      : isMed
      ? 'Moderate: Semi-Periodic Activity / Automated Polling'
      : 'Normal: Aperiodic / Human Interactive Traffic',
    insights,
  };
}

function BeaconingAnalysisCard({ beaconing: rawBeaconing, packets }) {
  const beaconing = resolveBeaconing(rawBeaconing, packets);

  if (!beaconing || beaconing.status === 'insufficient_data') {
    return (
      <div className="card" style={{
        padding: '1.25rem',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
      }}>
        <Radio style={{ width: 22, height: 22, color: 'var(--text-muted)', marginBottom: 8 }} />
        <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', margin: '0 0 4px' }}>
          C2 Beaconing & Timing Anomaly Analysis
        </p>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', margin: 0, lineHeight: 1.5 }}>
          {beaconing?.explanation || 'Insufficient packets to evaluate inter-arrival timing regularity.'}
        </p>
      </div>
    );
  }

  const score = beaconing.anomaly_score ?? 0;
  const isHigh = (score >= 68 || beaconing.beacon_detected) && !beaconing.is_small_sample;
  const isMed = !isHigh && (score >= 40 || beaconing.anomaly_level === 'ELEVATED');

  const badge = isHigh
    ? { bg: '#FEF2F2', border: '#FECACA', text: '#DC2626', label: 'HIGH ANOMALY (BEHAVIORAL)' }
    : isMed
    ? { bg: '#FFFBEB', border: '#FDE68A', text: '#D97706', label: 'ELEVATED / NOTICE' }
    : { bg: '#F0FDF4', border: '#BBF7D0', text: '#16A34A', label: 'NORMAL / APERIODIC' };

  const intervalsCount = beaconing.total_intervals_analyzed ?? beaconing.sample_size_intervals;

  return (
    <div className="card" style={{
      padding: '1.25rem',
      borderRadius: 12,
      border: `1px solid ${isHigh ? '#FECACA' : 'var(--border)'}`,
      backgroundColor: isHigh ? '#FFF5F5' : 'var(--bg-card)',
      display: 'flex',
      flexDirection: 'column',
      height: '100%',
      justifyContent: 'space-between',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            width: 30, height: 30, borderRadius: 8,
            backgroundColor: isHigh ? '#FEE2E2' : '#EFF6FF',
            display: 'flex', alignItems: 'center', justifyContent: 'center'
          }}>
            <Radio style={{ width: 16, height: 16, color: isHigh ? '#DC2626' : '#2563EB' }} />
          </div>
          <div>
            <h4 style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              C2 Beaconing & Timing Anomaly Analysis
            </h4>
            <p style={{ fontSize: 11, color: '#64748B', margin: 0 }}>
              Behavioral inter-arrival timing (IAT) regularity & automated cadence evaluation
            </p>
          </div>
        </div>

        <span style={{
          fontSize: 11, fontWeight: 700, padding: '3px 10px', borderRadius: 999,
          backgroundColor: badge.bg, border: `1px solid ${badge.border}`, color: badge.text
        }}>
          {badge.label}
        </span>
      </div>

      {/* Main Score & Metrics Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1rem' }}>
        <div className="card-surface" style={{ padding: '0.75rem', borderRadius: 8, textAlign: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
            <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anomaly Score</span>
            <span
              title="Beaconing Anomaly Score (0–100): Measures periodicity, timing regularity (IAT CV), and arrival jitter to detect automated scheduled callbacks (e.g. C2 or heartbeat probes)."
              style={{ cursor: 'help', display: 'flex', alignItems: 'center' }}
            >
              <HelpCircle size={11} style={{ color: 'var(--text-muted)' }} />
            </span>
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color: badge.text, marginTop: 2 }}>
            {score}<span style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-muted)' }}>/100</span>
          </div>
        </div>

        <div style={{ padding: '0.75rem', backgroundColor: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0', textAlign: 'center' }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Timing Regularity</span>
          <div style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>
            {beaconing.timing_regularity_pct}%
          </div>
        </div>

        <div style={{ padding: '0.75rem', backgroundColor: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0', textAlign: 'center' }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Estimated Interval</span>
          <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', marginTop: 6 }}>
            {beaconing.estimated_interval_sec != null ? `~${beaconing.estimated_interval_sec}s` : 'N/A'}
          </div>
          {beaconing.jitter_sec != null && (
            <span style={{ fontSize: 10, color: '#64748B' }}>±{beaconing.jitter_sec}s jitter</span>
          )}
        </div>

        <div style={{ padding: '0.75rem', backgroundColor: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0', textAlign: 'center' }}>
          <span style={{ fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Sample & Confidence</span>
          <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginTop: 6 }}>
            {beaconing.confidence_level || 'MODERATE'}
          </div>
          {intervalsCount != null && (
            <span style={{ fontSize: 10, color: '#64748B' }}>{intervalsCount} intervals</span>
          )}
        </div>
      </div>

      {/* Forensic Verdict & Insights */}
      <div style={{
        padding: '0.75rem 1rem',
        borderRadius: 8,
        backgroundColor: isHigh ? '#FEF2F2' : '#F1F5F9',
        borderLeft: `3px solid ${isHigh ? '#DC2626' : '#64748B'}`
      }}>
        <p style={{ fontSize: 12, fontWeight: 600, color: isHigh ? '#991B1B' : 'var(--text-primary)', margin: '0 0 4px 0' }}>
          {beaconing.verdict}
        </p>
        <ul style={{ margin: 0, paddingLeft: '1.2rem', fontSize: 11, color: '#475569', lineHeight: 1.6 }}>
          {beaconing.insights?.map((ins, idx) => (
            <li key={idx}>{ins}</li>
          ))}
        </ul>
      </div>

      {/* Behavioral Limitation Disclaimer */}
      <div style={{ marginTop: '0.75rem', fontSize: 11, color: '#64748B', display: 'flex', alignItems: 'center', gap: 6, fontStyle: 'italic' }}>
        <Info style={{ width: 13, height: 13, flexShrink: 0, color: '#94A3B8' }} />
        <span>
          Behavioral note: Timing regularity is an indicator, not definitive proof of compromise. Benign keepalives (e.g. DPD, NAT keepalive) and synthetic test scripts can also exhibit periodic intervals.
        </span>
      </div>
    </div>
  );
}

// ── Observation Badge with Tooltip ─────────────────────────────────────────
const OBSERVATION_TOOLTIPS = {
  Observed: 'Directly identified from the captured packet data.',
  Inferred: 'Derived from available packet information; not directly confirmed.',
};

function ObservationBadge({ observationType }) {
  const isInferred = observationType === 'Inferred';
  const label = observationType || 'Observed';
  const tooltipText = isInferred
    ? OBSERVATION_TOOLTIPS.Inferred
    : OBSERVATION_TOOLTIPS.Observed;

  const [hoverOpen, setHoverOpen] = useState(false);
  const [focusOpen, setFocusOpen] = useState(false);
  const [tapOpen, setTapOpen] = useState(false);
  const isVisible = hoverOpen || focusOpen || tapOpen;

  useEffect(() => {
    if (!tapOpen) return;
    const handleOutside = () => setTapOpen(false);
    const handleKey = (e) => {
      if (e.key === 'Escape') setTapOpen(false);
    };
    document.addEventListener('pointerdown', handleOutside);
    document.addEventListener('keydown', handleKey);
    return () => {
      document.removeEventListener('pointerdown', handleOutside);
      document.removeEventListener('keydown', handleKey);
    };
  }, [tapOpen]);

  return (
    <span
      style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', gap: 3 }}
      onMouseEnter={() => setHoverOpen(true)}
      onMouseLeave={() => setHoverOpen(false)}
    >
      <span style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        fontSize: 10,
        fontWeight: 600,
        padding: '1px 6px',
        borderRadius: 9999,
        backgroundColor: isInferred ? '#FFFBEB' : '#F0FDF4',
        color: isInferred ? '#B45309' : '#15803D',
        border: `1px solid ${isInferred ? '#FDE68A' : '#BBF7D0'}`,
      }}>
        {label}
        <button
          type="button"
          aria-label={`${label} info: ${tooltipText}`}
          aria-expanded={isVisible}
          onFocus={() => setFocusOpen(true)}
          onBlur={() => setFocusOpen(false)}
          onPointerDown={(e) => e.stopPropagation()}
          onClick={(e) => {
            e.stopPropagation();
            setTapOpen((prev) => !prev);
          }}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 0,
            margin: 0,
            border: 'none',
            background: 'transparent',
            color: 'inherit',
            cursor: 'pointer',
            lineHeight: 1,
            opacity: 0.85,
          }}
        >
          <Info style={{ width: 11, height: 11 }} />
        </button>
      </span>

      {isVisible && (
        <span
          role="tooltip"
          onClick={(e) => e.stopPropagation()}
          style={{
            position: 'absolute',
            bottom: 'calc(100% + 6px)',
            left: 0,
            zIndex: 30,
            width: 'max-content',
            maxWidth: 230,
            padding: '6px 9px',
            borderRadius: 6,
            backgroundColor: 'var(--text-primary)',
            color: '#F8FAFC',
            fontSize: 11,
            fontWeight: 500,
            lineHeight: 1.4,
            boxShadow: '0 4px 12px rgba(15, 23, 42, 0.18)',
            pointerEvents: 'none',
          }}
        >
          {tooltipText}
        </span>
      )}
    </span>
  );
}

// ── Network Forensics Timeline ─────────────────────────────────────────────
function NetworkForensicsTimeline({ events = [], totalCount = 0, onInspectPacket }) {
  const [filterProto, setFilterProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [sortOrder, setSortOrder]     = useState('oldest'); // 'oldest' | 'newest'
  const [expandedId, setExpandedId]   = useState(null);

  const availableProtos = useMemo(() => {
    const base = ['ALL', 'IKE', 'ESP', 'DNS', 'TCP', 'UDP'];
    const extras = new Set();
    (events || []).forEach(e => {
      const p = (e.protocol || '').toUpperCase();
      if (p && !base.includes(p)) extras.add(p);
    });
    return [...base, ...Array.from(extras)];
  }, [events]);

  const filteredAndSorted = useMemo(() => {
    if (!events || events.length === 0) return [];
    const q = searchQuery.trim().toLowerCase();
    const list = events.filter(evt => {
      const matchProto = filterProto === 'ALL' || (evt.protocol || '').toUpperCase() === filterProto;
      const matchSearch =
        !q ||
        evt.src_ip?.toLowerCase().includes(q) ||
        evt.dst_ip?.toLowerCase().includes(q) ||
        evt.description?.toLowerCase().includes(q) ||
        evt.event_type?.toLowerCase().includes(q) ||
        evt.protocol?.toLowerCase().includes(q) ||
        String(evt.packet_number).includes(q);
      return matchProto && matchSearch;
    });
    return sortOrder === 'newest' ? [...list].reverse() : list;
  }, [events, filterProto, searchQuery, sortOrder]);

  const eventStyle = (proto) => {
    switch ((proto || '').toUpperCase()) {
      case 'IKE':
      case 'ISAKMP':
        return { color: '#1D4ED8', bg: '#EFF6FF', border: '#BFDBFE', dot: '#2563EB', Icon: Key };
      case 'ESP':
        return { color: '#7E22CE', bg: '#F3E8FF', border: '#E9D5FF', dot: '#9333EA', Icon: Lock };
      case 'DNS':
        return { color: '#0F766E', bg: '#F0FDFA', border: '#99F6E4', dot: '#0D9488', Icon: Globe };
      case 'TCP':
        return { color: '#15803D', bg: '#F0FDF4', border: '#BBF7D0', dot: '#16A34A', Icon: Activity };
      case 'UDP':
        return { color: '#B45309', bg: '#FFFBEB', border: '#FDE68A', dot: '#D97706', Icon: Wifi };
      default:
        return { color: '#475569', bg: '#F1F5F9', border: '#E2E8F0', dot: '#64748B', Icon: Radio };
    }
  };

  if (!events || events.length === 0) {
    return (
      <div style={{
        padding: '2rem 1.25rem',
        textAlign: 'center',
        backgroundColor: '#F8FAFC',
        borderRadius: 8,
        border: '1px dashed #CBD5E1',
      }}>
        <Clock style={{ width: 22, height: 22, color: '#94A3B8', margin: '0 auto 8px' }} />
        <p style={{ fontSize: 13, fontWeight: 600, color: '#475569', margin: '0 0 4px' }}>
          No timeline events available
        </p>
        <p style={{ fontSize: 12, color: '#94A3B8', margin: 0 }}>
          Upload and analyze a valid PCAP capture to view the chronological sequence of network events.
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
      {/* Controls: Search, Protocol Filter, Sort Toggle */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <div style={{ position: 'relative' }}>
            <Search style={{ width: 13, height: 13, color: '#94A3B8', position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              placeholder="Search IP, event, or pkt #..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                fontSize: 12, padding: '4px 10px 4px 28px', borderRadius: 6,
                border: '1px solid #CBD5E1', outline: 'none', width: 205,
              }}
            />
          </div>
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} style={{ fontSize: 11, color: '#64748B', background: 'none', border: 'none', cursor: 'pointer' }}>
              Clear
            </button>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
            {availableProtos.map(proto => (
              <button
                key={proto}
                onClick={() => setFilterProto(proto)}
                style={{
                  fontSize: 11, fontWeight: 600, padding: '3px 8px', borderRadius: 4,
                  border: filterProto === proto ? '1px solid #2563EB' : '1px solid #E2E8F0',
                  backgroundColor: filterProto === proto ? '#EFF6FF' : '#FFFFFF',
                  color: filterProto === proto ? '#1D4ED8' : '#64748B',
                  cursor: 'pointer',
                }}>
                {proto}
              </button>
            ))}
          </div>

          <button
            type="button"
            onClick={() => setSortOrder(o => o === 'oldest' ? 'newest' : 'oldest')}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              fontSize: 11, fontWeight: 600, padding: '3px 9px', borderRadius: 4,
              border: '1px solid #CBD5E1', backgroundColor: '#F8FAFC', color: 'var(--text-secondary)',
              cursor: 'pointer',
            }}
            title="Toggle chronological sort order"
          >
            <ArrowUpDown style={{ width: 12, height: 12, color: '#2563EB' }} />
            {sortOrder === 'oldest' ? 'Oldest → Newest' : 'Newest → Oldest'}
          </button>
        </div>
      </div>

      {/* Status bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748B', flexWrap: 'wrap', gap: 6 }}>
        <span>
          Showing {filteredAndSorted.length} of {events.length} timeline events
          {totalCount > events.length && ` (from ${totalCount} total packets)`}
        </span>
        <span style={{ fontStyle: 'italic', color: '#94A3B8' }}>
          Click an event to expand details or inspect its packet
        </span>
      </div>

      {/* Vertical Chronological Timeline */}
      {filteredAndSorted.length === 0 ? (
        <div style={{ padding: '1.5rem', textAlign: 'center', color: '#64748B', fontSize: 12, backgroundColor: '#F8FAFC', borderRadius: 8, border: '1px solid #E2E8F0' }}>
          No timeline events match the current search or protocol filter.
        </div>
      ) : (
        <div style={{
          maxHeight: 460,
          overflowY: 'auto',
          paddingRight: 4,
          borderRadius: 8,
          border: '1px solid #E2E8F0',
          backgroundColor: '#FAFBFC',
          padding: '1rem',
        }}>
          <div style={{ position: 'relative', paddingLeft: 24, display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
            {/* Vertical Spine */}
            <div style={{
              position: 'absolute',
              left: 9,
              top: 10,
              bottom: 10,
              width: 2,
              backgroundColor: '#E2E8F0',
            }} />

            {filteredAndSorted.map((evt) => {
              const st = eventStyle(evt.protocol);
              const ProtoIcon = st.Icon;
              const isExpanded = expandedId === evt.event_id;
              const det = evt.details || {};

              return (
                <div key={evt.event_id} style={{ position: 'relative' }}>
                  {/* Timeline Node Dot */}
                  <div style={{
                    position: 'absolute',
                    left: -21,
                    top: 12,
                    width: 14,
                    height: 14,
                    borderRadius: '50%',
                    backgroundColor: '#FFFFFF',
                    border: `2.5px solid ${st.dot}`,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    zIndex: 2,
                  }} />

                  {/* Compact Event Card */}
                  <div
                    onClick={() => setExpandedId(isExpanded ? null : evt.event_id)}
                    style={{
                      borderRadius: 8,
                      border: isExpanded ? `1px solid ${st.dot}` : '1px solid #E2E8F0',
                      backgroundColor: '#FFFFFF',
                      padding: '0.625rem 0.875rem',
                      cursor: 'pointer',
                      transition: 'border-color 0.15s ease, box-shadow 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7, flexWrap: 'wrap' }}>
                        <span style={{
                          display: 'inline-flex', alignItems: 'center', gap: 4,
                          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 4,
                          backgroundColor: st.bg, color: st.color, border: `1px solid ${st.border}`,
                        }}>
                          <ProtoIcon style={{ width: 11, height: 11 }} />
                          {evt.protocol}
                        </span>
                        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
                          {evt.event_type}
                        </span>
                        <ObservationBadge observationType={evt.observation_type} />
                      </div>

                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: '#64748B', fontVariantNumeric: 'tabular-nums' }}>
                        {evt.relative_time && evt.timestamp !== evt.relative_time && (
                          <span style={{ color: '#94A3B8' }}>{evt.relative_time}</span>
                        )}
                        <span style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{evt.timestamp}</span>
                        <span style={{ fontSize: 10, fontWeight: 600, color: '#64748B', backgroundColor: '#F1F5F9', padding: '1px 6px', borderRadius: 4 }}>
                          #{evt.packet_number}
                        </span>
                        {isExpanded
                          ? <ChevronDown style={{ width: 13, height: 13, color: '#2563EB' }} />
                          : <ChevronRight style={{ width: 13, height: 13, color: '#94A3B8' }} />}
                      </div>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginTop: 4, flexWrap: 'wrap' }}>
                      <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: 0 }}>
                        {evt.description}
                      </p>
                      <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#64748B' }}>
                        {evt.src_ip}{evt.src_port ? `:${evt.src_port}` : ''} → {evt.dst_ip}{evt.dst_port ? `:${evt.dst_port}` : ''}
                      </span>
                    </div>

                    {/* Expandable Event Details */}
                    {isExpanded && (
                      <div
                        onClick={(e) => e.stopPropagation()}
                        style={{
                          marginTop: '0.625rem',
                          paddingTop: '0.625rem',
                          borderTop: '1px solid #F1F5F9',
                          display: 'flex',
                          flexDirection: 'column',
                          gap: 6,
                          fontSize: 11,
                        }}
                      >
                        {evt.observation_note && (
                          <div style={{ color: '#92400E', backgroundColor: '#FFFBEB', border: '1px solid #FDE68A', borderRadius: 4, padding: '4px 8px' }}>
                            {evt.observation_note}
                          </div>
                        )}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '0.5rem' }}>
                          <div>
                            <span style={{ color: '#64748B', fontWeight: 600 }}>Packet Size: </span>
                            <span style={{ color: 'var(--text-primary)' }}>{evt.length} bytes</span>
                          </div>
                          {det.ike_exchange && (
                            <div>
                              <span style={{ color: '#64748B', fontWeight: 600 }}>IKE Exchange: </span>
                              <span style={{ color: '#1D4ED8', fontWeight: 600 }}>{det.ike_exchange}</span>
                            </div>
                          )}
                          {det.ike_msg_id != null && (
                            <div>
                              <span style={{ color: '#64748B', fontWeight: 600 }}>Message ID: </span>
                              <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{det.ike_msg_id}</span>
                            </div>
                          )}
                          {det.esp_spi && (
                            <div>
                              <span style={{ color: '#64748B', fontWeight: 600 }}>ESP SPI: </span>
                              <span style={{ fontFamily: 'monospace', color: '#7E22CE', fontWeight: 600 }}>{det.esp_spi}</span>
                            </div>
                          )}
                          {det.esp_seq && (
                            <div>
                              <span style={{ color: '#64748B', fontWeight: 600 }}>ESP Seq: </span>
                              <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{det.esp_seq}</span>
                            </div>
                          )}
                          {det.dns_query && (
                            <div>
                              <span style={{ color: '#64748B', fontWeight: 600 }}>DNS Query: </span>
                              <span style={{ fontFamily: 'monospace', color: '#0F766E' }}>{det.dns_query}</span>
                            </div>
                          )}
                        </div>
                        {det.layers && det.layers.length > 0 && (
                          <div>
                            <span style={{ color: '#64748B', fontWeight: 600 }}>Layers: </span>
                            <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{det.layers.join(' ➔ ')}</span>
                          </div>
                        )}
                        {onInspectPacket && (
                          <div style={{ marginTop: 2 }}>
                            <button
                              type="button"
                              onClick={() => onInspectPacket(evt.packet_number)}
                              style={{
                                display: 'inline-flex', alignItems: 'center', gap: 5,
                                fontSize: 11, fontWeight: 600, color: '#2563EB',
                                backgroundColor: '#EFF6FF', border: '1px solid #BFDBFE',
                                borderRadius: 5, padding: '3px 9px', cursor: 'pointer',
                              }}
                            >
                              <ExternalLink style={{ width: 11, height: 11 }} />
                              Inspect Packet #{evt.packet_number} in Forensics Table
                            </button>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ── IKE Handshake Flow Diagram (Web UI) ──────────────────────────────────────
function IkeHandshakeFlowCard({ packets = [], ikeVersion = null }) {
  const ikePkts = (packets || []).filter(
    (p) => p && ['IKE', 'ISAKMP'].includes(String(p.protocol || '').toUpperCase())
  );

  if (ikePkts.length === 0) {
    return (
      <div style={{ fontSize: 12.5, color: 'var(--text-muted)', padding: '0.5rem 0' }}>
        No IKE/ISAKMP handshake packets were observed in this capture (Unavailable / Partial Capture).
      </div>
    );
  }

  const observed = ikePkts.map((p) => {
    const det = p.details && typeof p.details === 'object' ? p.details : {};
    const exch = det.ike_exchange || 'Unknown Exchange';
    const isResp = det.ike_is_response;
    const role = isResp === false ? 'Request' : isResp === true ? 'Response' : 'Unknown';
    const pktNo = p.number ?? p.packet_no ?? '?';
    const ts = p.timestamp || '—';
    return { exchange: exch, role, pktNo, ts };
  });

  const ver = ikeVersion || 'Unknown';
  const missing = [];
  if (ver === 'IKEv2') {
    for (const ex of ['IKE_SA_INIT', 'IKE_AUTH']) {
      for (const rl of ['Request', 'Response']) {
        if (!observed.some((o) => o.exchange === ex && o.role === rl)) {
          missing.push(`${ex} ${rl}`);
        }
      }
    }
  } else if (ver === 'IKEv1') {
    if (!observed.some((o) => ['Identity Protection (Main Mode)', 'Aggressive Mode'].includes(o.exchange))) {
      missing.push('Phase 1 (Main Mode / Aggressive Mode)');
    }
    if (!observed.some((o) => o.exchange === 'Quick Mode')) {
      missing.push('Phase 2 (Quick Mode)');
    }
  }

  const statusLabel = missing.length > 0 ? 'Partial Capture' : 'Observed Exchanges Complete';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', fontSize: 12, color: 'var(--text-secondary)' }}>
        <span><strong>Protocol:</strong> {ver}</span>
        <span>•</span>
        <span><strong>Observed IKE Packets:</strong> {observed.length}</span>
        <span>•</span>
        <span><strong>Status:</strong> {statusLabel}</span>
      </div>

      <div style={{
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: '0.875rem 1rem',
        backgroundColor: 'var(--bg-subtle, rgba(148,163,184,0.06))',
        display: 'flex',
        flexDirection: 'column',
        gap: '0.6rem',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, fontWeight: 700, color: 'var(--text-primary)', paddingBottom: 4, borderBottom: '1px solid var(--border)' }}>
          <span>Initiator</span>
          <span>Responder</span>
        </div>

        {observed.slice(0, 12).map((item, idx) => {
          const isReq = item.role === 'Request';
          const isRes = item.role === 'Response';
          const color = isReq ? '#6366F1' : isRes ? '#10B981' : '#F59E0B';
          const arrow = isReq ? '───▶' : isRes ? '◀───' : '┄┄┄┄';
          return (
            <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, fontSize: 12 }}>
              <span style={{ color, fontWeight: 700, minWidth: 38 }}>{isReq ? 'REQ' : isRes ? 'RESP' : 'UNK'}</span>
              <div style={{ flex: 1, textAlign: 'center', color: 'var(--text-primary)' }}>
                <span style={{ fontWeight: 600 }}>Pkt #{item.pktNo}</span>{' '}
                <span style={{ color: 'var(--text-muted)' }}>({item.ts})</span>{' '}
                <span style={{ color, fontWeight: 700, margin: '0 6px' }}>{arrow}</span>{' '}
                <span>{item.exchange}</span>
              </div>
              <span style={{ minWidth: 38 }} />
            </div>
          );
        })}
      </div>

      {missing.length > 0 && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
          <strong>Not Observed / Unavailable ({statusLabel}):</strong> {missing.join(', ')}
        </div>
      )}
    </div>
  );
}

// ── Packet-Level Forensics Table ───────────────────────────────────────────
function PacketForensicsTable({ packets = [], totalCount = 0, selectedPacketNumber = null }) {
  const [filterProto, setFilterProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState(null);

  useEffect(() => {
    if (selectedPacketNumber != null) {
      setFilterProto('ALL');
      setSearchQuery('');
      setExpandedRow(selectedPacketNumber);
    }
  }, [selectedPacketNumber]);

  const toggleRow = (num) => {
    setExpandedRow(expandedRow === num ? null : num);
  };

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return packets.filter(p => {
      const matchProto = filterProto === 'ALL' || p.protocol?.toUpperCase() === filterProto.toUpperCase();
      const src = (p.src_ip ?? p.src ?? '').toString().toLowerCase();
      const dst = (p.dst_ip ?? p.dst ?? '').toString().toLowerCase();
      const info = (p.info ?? '').toString().toLowerCase();
      const proto = (p.protocol ?? '').toString().toLowerCase();
      const num = String(p.number ?? p.packet_no ?? p.frame_number ?? '');
      const matchSearch =
        !q ||
        src.includes(q) ||
        dst.includes(q) ||
        info.includes(q) ||
        proto.includes(q) ||
        num.includes(q);
      return matchProto && matchSearch;
    });
  }, [packets, filterProto, searchQuery]);

  const protoBadge = (proto) => {
    switch (proto?.toUpperCase()) {
      case 'ESP':   return { bg: '#F3E8FF', text: '#7E22CE', border: '#E9D5FF' };
      case 'IKE':
      case 'ISAKMP': return { bg: '#EFF6FF', text: '#1D4ED8', border: '#BFDBFE' };
      case 'TCP':   return { bg: '#F0FDF4', text: '#15803D', border: '#BBF7D0' };
      case 'UDP':   return { bg: '#FFFBEB', text: '#B45309', border: '#FDE68A' };
      default:      return { bg: '#F1F5F9', text: '#475569', border: '#E2E8F0' };
    }
  };

  if (!packets || packets.length === 0) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center', color: '#94A3B8', fontSize: 13, backgroundColor: '#F8FAFC', borderRadius: 8 }}>
        No packet-level data available. Run analysis on a PCAP file to view packet forensics.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
      {/* Controls: search and protocol filter */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ position: 'relative' }}>
            <Search style={{ width: 13, height: 13, color: '#94A3B8', position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)' }} />
            <input
              type="text"
              placeholder="Search IP, info or #..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                fontSize: 12, padding: '4px 10px 4px 28px', borderRadius: 6,
                border: '1px solid #CBD5E1', outline: 'none', width: 190,
              }}
            />
          </div>
          {searchQuery && (
            <button onClick={() => setSearchQuery('')} style={{ fontSize: 11, color: '#64748B', background: 'none', border: 'none', cursor: 'pointer' }}>
              Clear
            </button>
          )}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          {['ALL', 'IKE', 'ESP', 'UDP', 'TCP'].map(proto => (
            <button
              key={proto}
              onClick={() => setFilterProto(proto)}
              style={{
                fontSize: 11, fontWeight: 600, padding: '3px 8px', borderRadius: 4,
                border: filterProto === proto ? '1px solid #2563EB' : '1px solid #E2E8F0',
                backgroundColor: filterProto === proto ? '#EFF6FF' : '#FFFFFF',
                color: filterProto === proto ? '#1D4ED8' : '#64748B',
                cursor: 'pointer',
              }}>
              {proto}
            </button>
          ))}
        </div>
      </div>

      {/* Packet count status note */}
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#64748B' }}>
        <span>
          Showing {filtered.length} of {packets.length} extracted packets
          {totalCount > packets.length && ` (from ${totalCount} total in capture)`}
        </span>
        <span style={{ fontStyle: 'italic', color: '#94A3B8' }}>Click any row to toggle forensic details</span>
      </div>

      {/* Table */}
      <div style={{ borderRadius: 8, border: '1px solid #E2E8F0', overflow: 'hidden', backgroundColor: '#FFFFFF' }}>
        <div style={{ overflowX: 'auto', maxHeight: 420 }}>
          <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead style={{ position: 'sticky', top: 0, backgroundColor: '#F8FAFC', zIndex: 10, borderBottom: '1px solid #E2E8F0' }}>
              <tr>
                <th style={{ padding: '0.5rem 0.625rem', width: 36 }}></th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>#</th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Time</th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Source IP</th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Destination IP</th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Protocol</th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Length</th>
                <th style={{ padding: '0.5rem 0.625rem', fontSize: 10, fontWeight: 600, color: '#64748B', textTransform: 'uppercase' }}>Info</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(pkt => {
                const isExpanded = expandedRow === pkt.number;
                const b = protoBadge(pkt.protocol);
                return (
                  <tr
                    key={pkt.number}
                    onClick={() => toggleRow(pkt.number)}
                    style={{
                      borderBottom: '1px solid #F1F5F9',
                      cursor: 'pointer',
                      backgroundColor: isExpanded ? '#F0F9FF' : 'transparent',
                    }}>
                    <td style={{ padding: '0.5rem 0.625rem', textAlign: 'center', color: '#94A3B8' }}>
                      {isExpanded ? <ChevronDown style={{ width: 13, height: 13, color: '#2563EB' }} /> : <ChevronRight style={{ width: 13, height: 13 }} />}
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', fontWeight: 600, color: '#475569' }}>
                      {pkt.number}
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', color: '#64748B', fontVariantNumeric: 'tabular-nums' }}>
                      {pkt.timestamp}
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                      {pkt.src_ip}
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'monospace', color: 'var(--text-primary)' }}>
                      {pkt.dst_ip}
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem' }}>
                      <span style={{
                        fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                        backgroundColor: b.bg, color: b.text, border: `1px solid ${b.border}`
                      }}>
                        {pkt.protocol}
                      </span>
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', color: '#475569', fontVariantNumeric: 'tabular-nums' }}>
                      {pkt.length} B
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', color: 'var(--text-secondary)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={pkt.info}>
                      {pkt.info}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Expandable Forensic Details Drawer */}
        {expandedRow !== null && (() => {
          const ep = packets.find(p => p.number === expandedRow);
          if (!ep) return null;
          const det = ep.details || {};
          return (
            <div style={{ padding: '0.875rem 1.25rem', backgroundColor: '#F8FAFC', borderTop: '2px solid #BFDBFE' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Binary style={{ width: 14, height: 14, color: '#2563EB' }} />
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
                    Packet #{ep.number} Forensic Detail
                  </span>
                </div>
                <button
                  onClick={() => setExpandedRow(null)}
                  style={{ fontSize: 11, color: '#64748B', background: 'none', border: 'none', cursor: 'pointer' }}>
                  Close
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', fontSize: 11 }}>
                <div>
                  <span style={{ color: '#64748B', fontWeight: 600 }}>IP Flow: </span>
                  <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{ep.src_ip} → {ep.dst_ip}</span>
                </div>
                {det.src_port && (
                  <div>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>Ports: </span>
                    <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{det.src_port} → {det.dst_port}</span>
                  </div>
                )}
                {det.esp_spi && (
                  <div>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>ESP SPI: </span>
                    <span style={{ fontFamily: 'monospace', color: '#7E22CE', fontWeight: 700 }}>{det.esp_spi}</span>
                  </div>
                )}
                {det.esp_seq && (
                  <div>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>ESP Sequence #: </span>
                    <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{det.esp_seq}</span>
                  </div>
                )}
                {det.ike_exchange && (
                  <div>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>IKE Exchange: </span>
                    <span style={{ color: '#1D4ED8', fontWeight: 600 }}>{det.ike_exchange}</span>
                  </div>
                )}
                {det.ike_msg_id && (
                  <div>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>Message ID: </span>
                    <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{det.ike_msg_id}</span>
                  </div>
                )}
                {det.layers && det.layers.length > 0 && (
                  <div style={{ gridColumn: '1 / -1' }}>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>Protocol Layer Stack: </span>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{det.layers.join(' ➔ ')}</span>
                  </div>
                )}
              </div>
            </div>
          );
        })()}
      </div>
    </div>
  );
}

// ── Section Header ─────────────────────────────────────────────────────────
function SectionHead({ icon: Icon, title, action }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon style={{ width: 15, height: 15, color: '#2563EB' }} />
        <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{title}</span>
      </div>
      {action}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────
export default function AnalysisDetail() {
  const { id }       = useParams();
  const location     = useLocation();
  const navigate     = useNavigate();
  const [result, setResult] = useState(location.state?.result || null);
  const [loading, setLoading] = useState(!result);
  const [error,   setError]   = useState(null);
  const [selectedPacketNumber, setSelectedPacketNumber] = useState(null);

  useEffect(() => {
    if (!result && id) {
      setLoading(true);
      api.getById(id)
        .then(setResult)
        .catch(() => setError('Analysis not found.'))
        .finally(() => setLoading(false));
    }
  }, [id]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '5rem', gap: 10, color: '#94A3B8', fontSize: 14 }}>
      <RefreshCw style={{ width: 16, height: 16, animation: 'spin 1s linear infinite' }} /> Loading analysis…
    </div>
  );

  if (error || !result) return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: '5rem', gap: '1rem' }}>
      <Shield style={{ width: 40, height: 40, color: '#CBD5E1' }} />
      <p style={{ fontSize: 13, color: '#64748B' }}>{error || 'No analysis data found.'}</p>
      <button onClick={() => navigate('/history')} className="btn-secondary">← Back to History</button>
    </div>
  );

  const { filename, pcap_metrics: m, security_assessment: sa, ml_prediction: ml } = result;
  const createdAt = result.created_at;
  const rc    = riskColor(sa?.risk_level);
  const highF = (sa?.findings || []).filter(f => f.severity !== 'Informational');
  const infoF = (sa?.findings || []).filter(f => f.severity === 'Informational');

  // Risk card accent color
  const riskAccent =
    sa?.risk_level === 'High' || sa?.risk_level === 'Critical' ? { bg: '#FEF2F2', border: '#FECACA', text: '#DC2626' } :
    sa?.risk_level === 'Medium' ? { bg: '#FFFBEB', border: '#FDE68A', text: '#D97706' } :
    sa?.risk_level === 'Low'    ? { bg: '#EFF6FF', border: '#BFDBFE', text: '#2563EB' } :
    { bg: '#F0FDF4', border: '#BBF7D0', text: '#16A34A' };

  return (
    <div style={{ maxWidth: '72rem', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.25rem', paddingBottom: '3rem' }}>

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
        <div>
          <button onClick={() => navigate(-1)}
            style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, color: '#64748B', background: 'none', border: 'none', cursor: 'pointer', marginBottom: 8, padding: 0 }}>
            <ArrowLeft style={{ width: 13, height: 13 }} /> Back
          </button>
          <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>Analysis Report</h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: '#94A3B8' }}>
            <span style={{ fontFamily: 'monospace', maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={filename}>
              {filename}
            </span>
            {createdAt && <span>· {fmtDate(createdAt)}</span>}
          </div>
        </div>
        <a href={api.reportUrl(id)} target="_blank" rel="noreferrer" className="btn-secondary" style={{ fontSize: 13, flexShrink: 0 }}>
          <Download style={{ width: 13, height: 13 }} /> Download PDF
        </a>
      </div>

      {/* ── UPPER SECTION: Written Analysis, Risk Assessment, Findings & Evidence ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, paddingBottom: '0.25rem' }}>
          <FileText style={{ width: 16, height: 16, color: 'var(--blue)' }} />
          <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Written Analysis, Risk Assessment & Security Findings
          </h2>
        </div>

        {/* Security Analysis & Risk Assessment Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem', alignItems: 'stretch' }}>
          {/* Protocol Summary Card */}
          <div className="card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <SectionHead icon={Layers} title="Protocol Summary (Security Analysis)" />
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.625rem', marginTop: '0.75rem' }}>
                <MetricCard icon={Activity} label="Packet Count" value={String(m?.packet_count ?? '—')} />
                <MetricCard icon={Key}      label="IKE Version"  value={m?.ike_version} />
                <MetricCard icon={Wifi}     label="Protocols"    value={m?.protocols_found?.join(', ')} />
                <MetricCard icon={Shield}   label="VPN Mode"
                  value={
                    m?.vpn_mode_inferred?.startsWith('Tunnel')    ? 'Tunnel' :
                    m?.vpn_mode_inferred?.startsWith('Transport') ? 'Transport' : 'Not Extracted'
                  }
                />
              </div>
            </div>
            {m?.vpn_mode_inferred?.includes('Inferred') && (
              <div className="alert-warn" style={{ marginTop: '0.875rem' }}>
                <AlertCircle style={{ width: 13, height: 13, color: '#B45309', flexShrink: 0, marginTop: 1 }} />
                <p style={{ fontSize: 11, color: '#92400E', margin: 0 }}>
                  VPN Mode is inferred from observable packet characteristics, not definitively determined.
                </p>
              </div>
            )}
          </div>

          {/* Overall Risk Score */}
          <div style={{
            borderRadius: 14, border: `1px solid ${riskAccent.border}`,
            backgroundColor: riskAccent.bg, padding: '1.5rem',
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            textAlign: 'center', gap: '0.5rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <p style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text-muted)', margin: 0 }}>
                Overall Risk Assessment
              </p>
              <span
                title="Overall Risk Score (0–100): Calculated by evaluating cryptographic parameters (IKE version, DH group, encryption cipher) and payload protection against security rules."
                style={{ cursor: 'help', display: 'flex', alignItems: 'center' }}
              >
                <HelpCircle size={13} style={{ color: 'var(--text-muted)' }} />
              </span>
            </div>
            <div style={{ fontSize: '3.5rem', fontWeight: 800, color: riskAccent.text, lineHeight: 1 }}>
              {sa?.overall_risk_score ?? 0}
            </div>
            <span className={`badge ${rc.badge}`} style={{ fontSize: '0.8rem', padding: '0.3rem 0.875rem' }}>
              {sa?.risk_level ?? 'Unknown'}
            </span>
            {sa?.score_explanation && (
              <p style={{ fontSize: 11, color: '#64748B', lineHeight: 1.65, marginTop: 4, maxWidth: 220 }}>
                {sa.score_explanation}
              </p>
            )}
          </div>
        </div>

        {/* Cryptographic Parameters */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <SectionHead icon={Lock} title="Cryptographic Parameters" />
          <CryptoRow label="Encryption Algorithm"   value={m?.encryption} />
          <CryptoRow label="Key Exchange (DH Group)" value={m?.key_exchange} />
          <CryptoRow label="Authentication Method"   value={m?.authentication} />
          <p style={{ fontSize: 11, color: '#94A3B8', marginTop: 12, paddingTop: 12, borderTop: '1px solid #F1F5F9', lineHeight: 1.65, margin: 0 }}>
            Values marked "Not Extracted" were not observable. IKE negotiation parameters are only visible if
            the IKE_SA_INIT exchange is present in the capture.
          </p>
        </div>

        {/* Evidence-Based Security Findings & Recommendations */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <SectionHead
            icon={AlertTriangle}
            title="Evidence-Based Security Findings & Recommendations"
            action={<span style={{ fontSize: 12, color: '#94A3B8' }}>{sa?.findings?.length ?? 0} finding{sa?.findings?.length !== 1 ? 's' : ''}</span>}
          />

          {sa?.overall_risk_score === 0 && (
            <div className="alert-warn" style={{ marginBottom: '1rem', marginTop: '0.5rem' }}>
              <AlertCircle style={{ width: 13, height: 13, color: '#B45309', flexShrink: 0, marginTop: 1 }} />
              <div>
                <p style={{ fontSize: 12, fontWeight: 600, color: '#92400E', marginBottom: 2 }}>
                  Risk Score 0 — does not mean the VPN is fully secure
                </p>
                <p style={{ fontSize: 11, color: '#B45309', lineHeight: 1.6, margin: 0 }}>
                  A score of 0 means no high-risk values were found among the extractable parameters.{' '}
                  {sa?.rules_skipped?.length > 0
                    ? `${sa.rules_skipped.length} rule(s) were skipped because parameters were not visible.`
                    : 'All observable parameters passed.'}
                </p>
              </div>
            </div>
          )}

          {(sa?.findings?.length ?? 0) === 0 ? (
            <p style={{ fontSize: 13, color: '#94A3B8', textAlign: 'center', padding: '1.5rem' }}>No security findings.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem', marginTop: '0.75rem' }}>
              {highF.map((f, i) => <FindingCard key={i} f={f} />)}
              {infoF.length > 0 && (
                <>
                  <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginTop: 8, marginBottom: 0 }}>
                    Informational & Hardening Observations
                  </p>
                  {infoF.map((f, i) => <FindingCard key={`info-${i}`} f={f} />)}
                </>
              )}
            </div>
          )}

          <AnalysisCoverageSummary evaluated={sa?.rules_evaluated ?? []} skipped={sa?.rules_skipped ?? []} />
          <RuleAudit evaluated={sa?.rules_evaluated} skipped={sa?.rules_skipped} />
        </div>
      </div>

      {/* ── LOWER SECTION: Data Visualizations & Traffic Graphs ────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '0.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--border)', paddingTop: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <BarChart3 style={{ width: 16, height: 16, color: 'var(--blue)' }} />
            <h2 style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Traffic Visualizations & Behavioral Analytics
            </h2>
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Flow Timing & Cadence Telemetry</span>
        </div>

        {/* Row 1: 2-Column Desktop Grid (Main Bar Graph + Packet-Size Distribution) */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '1rem',
          alignItems: 'stretch',
        }}>
          <ClassProbabilityCard ml={ml} />
          <PacketDistributionCard distribution={m?.packet_size_distribution} stats={m?.packet_size_stats} />
        </div>

        {/* Row 2: 2-Column Desktop Grid (XAI Decision Factors + C2 Beaconing Cadence) */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
          gap: '1rem',
          alignItems: 'stretch',
        }}>
          <XaiCard ml={ml} />
          <BeaconingAnalysisCard beaconing={m?.beaconing_analysis} packets={m?.packets} />
        </div>
      </div>

      {/* ── PACKET EVIDENCE ─────────────────────────────────────────────── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
        {/* Packet-Level Evidence (Forensics Dissection Table) */}
        <div id="packet-forensics-section" className="card" style={{ padding: '1.25rem' }}>
          <SectionHead icon={Binary} title="Packet-Level Evidence & Dissection Forensics" />
          <PacketForensicsTable
            packets={m?.packets}
            totalCount={m?.packet_count}
            selectedPacketNumber={selectedPacketNumber}
          />
        </div>
      </div>

    </div>
  );
}
