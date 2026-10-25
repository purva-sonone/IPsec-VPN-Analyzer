import { useState, useEffect, useMemo } from 'react';
import { useParams, useLocation, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Download, Shield, Activity, Lock, Key, Wifi,
  AlertTriangle, CheckCircle, XCircle, Info, Cpu, FlaskConical,
  SkipForward, ListChecks, AlertCircle, Layers, RefreshCw,
  Search, ChevronDown, ChevronRight, BarChart3, Binary, Wrench, FileSearch
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
      <p style={{ fontSize: 13, fontWeight: 600, color: empty ? '#94A3B8' : '#0F172A', fontStyle: empty ? 'italic' : 'normal' }}>
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
        <span style={{ fontSize: 13, fontWeight: 500, textAlign: 'right', maxWidth: 240, color: empty ? '#94A3B8' : '#0F172A', fontStyle: empty ? 'italic' : 'normal' }}>
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
          <span style={{ fontSize: 13, fontWeight: 700, color: '#0F172A' }}>{f.title}</span>
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
            <span style={{ fontWeight: 600, color: '#334155' }}>PCAP Evidence: </span>
            <span style={{ color: '#0F172A', fontFamily: 'monospace' }}>{f.evidence}</span>
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
                <td style={{ padding: '0.625rem 0.875rem', fontWeight: 500, color: '#0F172A' }}>{r.rule}</td>
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
          <p style={{ fontSize: 14, fontWeight: 700, color: '#0F172A' }}>{stats?.min_size ?? 0} B</p>
        </div>
        <div style={{ padding: '0.5rem 0.875rem', borderRadius: 6, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', flex: 1 }}>
          <p style={{ fontSize: 10, fontWeight: 600, color: '#94A3B8', textTransform: 'uppercase' }}>Average Size</p>
          <p style={{ fontSize: 14, fontWeight: 700, color: '#2563EB' }}>{stats?.avg_size ?? 0} B</p>
        </div>
        <div style={{ padding: '0.5rem 0.875rem', borderRadius: 6, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0', flex: 1 }}>
          <p style={{ fontSize: 10, fontWeight: 600, color: '#94A3B8', textTransform: 'uppercase' }}>Max Size</p>
          <p style={{ fontSize: 14, fontWeight: 700, color: '#0F172A' }}>{stats?.max_size ?? 0} B</p>
        </div>
      </div>

      {/* Horizontal Distribution Bars */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
        {distribution.map(d => {
          const barWidth = d.percentage > 0 ? Math.max((d.percentage / maxPct) * 100, 2) : 0;
          return (
            <div key={d.bin} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                <span style={{ fontWeight: 600, color: '#334155' }}>{d.bin}</span>
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
const ML_COLORS = { C2: '#DC2626', CHAT: '#2563EB', FILE_TRANSFER: '#16A34A', STREAMING: '#D97706', VOIP: '#7C3AED' };

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
      <span style={{ fontWeight: 700, color: ML_COLORS[d.name] || '#334155' }}>{d.name}</span>
      <span style={{ color: '#64748B', marginLeft: 8 }}>{d.value}%</span>
    </div>
  );
}

function MLSection({ ml, distribution, stats }) {
  if (!ml) return null;
  const { model_status, model_note, predicted_category, confidence_score,
          all_class_probabilities, dataset_note } = ml;

  const confPct = confidence_score != null ? parseFloat((confidence_score * 100).toFixed(1)) : null;
  const probaArr = all_class_probabilities
    ? Object.entries(all_class_probabilities)
        .map(([name, value]) => ({ name, value: parseFloat((value * 100).toFixed(1)) }))
        .sort((a, b) => b.value - a.value)
    : [];

  // Determine confidence/ambiguity flags (only when a trained model result exists)
  const isLowConf   = confPct != null && confPct < LOW_CONF_THRESHOLD;
  const spread      = probaArr.length >= 2 ? probaArr[0].value - probaArr[1].value : null;
  const isAmbiguous = spread != null && spread < AMBIG_SPREAD_THRESHOLD;
  const isC2        = predicted_category === 'C2';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {/* Status banner */}
      {model_status === 'not_applicable' ? (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
          <AlertCircle style={{ width: 15, height: 15, color: '#64748B', flexShrink: 0, marginTop: 1 }} />
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#334155', marginBottom: 2 }}>Classification Not Applicable</p>
            <p style={{ fontSize: 12, color: '#64748B', lineHeight: 1.6 }}>{model_note}</p>
          </div>
        </div>
      ) : model_status !== 'trained_model' ? (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: '#FFFBEB', border: '1px solid #FDE68A' }}>
          <AlertTriangle style={{ width: 15, height: 15, color: '#D97706', flexShrink: 0, marginTop: 1 }} />
          <div>
            <p style={{ fontSize: 13, fontWeight: 600, color: '#92400E', marginBottom: 2 }}>Model Notice</p>
            <p style={{ fontSize: 12, color: '#B45309', lineHeight: 1.6 }}>{model_note}</p>
          </div>
        </div>
      ) : (
        <>
          {/* Active model notice */}
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '0.75rem 0.875rem', borderRadius: 8, backgroundColor: '#F5F3FF', border: '1px solid #DDD6FE' }}>
            <FlaskConical style={{ width: 14, height: 14, color: '#7C3AED', flexShrink: 0, marginTop: 1 }} />
            <p style={{ fontSize: 11, color: '#6D28D9', lineHeight: 1.6 }}>
              <strong>Random Forest Traffic Classifier Active.</strong>{' '}
              {dataset_note || 'Trained on MIT Lincoln Laboratory VNAT Feature Dataframe (15,093 samples).'}
            </p>
          </div>

          {/* Prediction & Confidence Block */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div style={{ padding: '1.25rem', borderRadius: 10, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
              <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginBottom: 6 }}>
                Predicted Traffic Category
              </p>
              <p style={{ fontSize: '1.75rem', fontWeight: 800, color: ML_COLORS[predicted_category] || '#6D28D9', lineHeight: 1.1 }}>
                {predicted_category}
              </p>
              <p style={{ fontSize: 11, color: '#64748B', marginTop: 6 }}>
                Inferred from inter-arrival timing &amp; flow volume metrics
              </p>
            </div>

            <div style={{ padding: '1.25rem', borderRadius: 10, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
              <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginBottom: 6 }}>
                Model Confidence Score
              </p>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span style={{ fontSize: '1.75rem', fontWeight: 800, color: '#0F172A', lineHeight: 1.1 }}>
                  {confPct != null ? `${confPct}%` : 'N/A'}
                </span>
                <span style={{ fontSize: 11, color: '#64748B' }}>probability</span>
              </div>
              {confPct != null && (
                <div style={{ height: 6, width: '100%', backgroundColor: '#E2E8F0', borderRadius: 3, marginTop: 10, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', width: `${confPct}%`,
                    backgroundColor: confPct > 75 ? '#16A34A' : confPct > LOW_CONF_THRESHOLD ? '#2563EB' : '#D97706',
                    borderRadius: 3, transition: 'width 0.4s ease',
                  }} />
                </div>
              )}
            </div>
          </div>

          {/* ── Confidence / Ambiguity Caution Notes ────────────────────── */}
          {(isLowConf || isAmbiguous) && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 10,
              padding: '0.75rem 1rem', borderRadius: 8,
              backgroundColor: '#FFFBEB', border: '1px solid #FDE68A',
            }}>
              <AlertTriangle style={{ width: 14, height: 14, color: '#D97706', flexShrink: 0, marginTop: 1 }} />
              <div>
                <p style={{ fontSize: 12, fontWeight: 600, color: '#92400E', marginBottom: 3 }}>
                  {isLowConf && isAmbiguous
                    ? 'Low Confidence & Ambiguous Prediction'
                    : isLowConf ? 'Low Confidence Prediction'
                    : 'Ambiguous Prediction'}
                </p>
                <p style={{ fontSize: 11, color: '#B45309', lineHeight: 1.6 }}>
                  {isLowConf && `Confidence is ${confPct}%, below the ${LOW_CONF_THRESHOLD}% threshold. `}
                  {isAmbiguous && spread != null && `The top two categories differ by only ${spread.toFixed(1)} pp (threshold: ${AMBIG_SPREAD_THRESHOLD} pp). `}
                  The classifier's output should be treated as indicative for this capture.
                </p>
              </div>
            </div>
          )}

          {/* ── C2 Classification Caution ────────────────────────────────── */}
          {isC2 && (
            <div style={{
              display: 'flex', alignItems: 'flex-start', gap: 10,
              padding: '0.75rem 1rem', borderRadius: 8,
              backgroundColor: '#FEF2F2', border: '1px solid #FECACA',
            }}>
              <Info style={{ width: 14, height: 14, color: '#B91C1C', flexShrink: 0, marginTop: 1 }} />
              <div>
                <p style={{ fontSize: 12, fontWeight: 600, color: '#991B1B', marginBottom: 3 }}>
                  C2 Classification — Does Not Confirm Malicious Activity
                </p>
                <p style={{ fontSize: 11, color: '#B91C1C', lineHeight: 1.6 }}>
                  The model predicts <strong>C2 (Command &amp; Control)</strong> traffic patterns based on flow
                  timing and volume statistics. This is a <em>traffic category</em> label from the VNAT
                  dataset — it does not confirm that the VPN carries malicious traffic or that a
                  cyberattack is underway. The same flow features can appear in legitimate control-plane
                  or management traffic. Treat this as a signal for further investigation only.
                </p>
              </div>
            </div>
          )}

          {/* ── Class Probability Bar Chart (Recharts) ───────────────────── */}
          {probaArr.length > 0 && (
            <div style={{ borderRadius: 8, border: '1px solid #E2E8F0', overflow: 'hidden' }}>
              <p style={{
                padding: '0.5rem 0.875rem', fontSize: 10, fontWeight: 600,
                textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8',
                borderBottom: '1px solid #F1F5F9', backgroundColor: '#F8FAFC',
              }}>
                Class Probability Breakdown
              </p>
              <div style={{ padding: '0.875rem 1rem' }}>
                <ResponsiveContainer width="100%" height={probaArr.length * 36 + 8}>
                  <BarChart
                    data={probaArr}
                    layout="vertical"
                    margin={{ top: 0, right: 40, left: 80, bottom: 0 }}
                    barSize={14}
                  >
                    <XAxis
                      type="number"
                      domain={[0, 100]}
                      tickFormatter={v => `${v}%`}
                      tick={{ fontSize: 10, fill: '#94A3B8' }}
                      axisLine={false}
                      tickLine={false}
                    />
                    <YAxis
                      type="category"
                      dataKey="name"
                      tick={{ fontSize: 11, fontWeight: 600, fill: '#334155' }}
                      axisLine={false}
                      tickLine={false}
                      width={76}
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
                <p style={{ fontSize: 10, color: '#94A3B8', marginTop: 4, textAlign: 'right' }}>
                  Highlighted bar = predicted category
                </p>
              </div>
            </div>
          )}

          {/* Model Note — classification scope disclaimer */}
          <p style={{ fontSize: 11, color: '#64748B', lineHeight: 1.65, borderLeft: '2px solid #DDD6FE', paddingLeft: '0.75rem' }}>
            {model_note}
          </p>
        </>
      )}

      {/* ── Packet Size Distribution ── */}
      <div style={{ marginTop: '0.5rem', borderTop: '1px solid #E2E8F0', paddingTop: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: '0.75rem' }}>
          <BarChart3 style={{ width: 14, height: 14, color: '#2563EB' }} />
          <span style={{ fontSize: 12, fontWeight: 700, color: '#0F172A', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Packet-Size Distribution (Actual PCAP Data)
          </span>
        </div>
        <PacketSizeDistribution distribution={distribution} stats={stats} />
      </div>
    </div>
  );
}

// ── Packet-Level Forensics Table ───────────────────────────────────────────
function PacketForensicsTable({ packets = [], totalCount = 0 }) {
  const [filterProto, setFilterProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState(null);

  const toggleRow = (num) => {
    setExpandedRow(expandedRow === num ? null : num);
  };

  const filtered = useMemo(() => {
    return packets.filter(p => {
      const matchProto = filterProto === 'ALL' || p.protocol?.toUpperCase() === filterProto.toUpperCase();
      const matchSearch =
        !searchQuery ||
        p.src_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.dst_ip?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        p.info?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        String(p.number).includes(searchQuery);
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
                    <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'monospace', color: '#0F172A' }}>
                      {pkt.src_ip}
                    </td>
                    <td style={{ padding: '0.5rem 0.625rem', fontFamily: 'monospace', color: '#0F172A' }}>
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
                    <td style={{ padding: '0.5rem 0.625rem', color: '#334155', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={pkt.info}>
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
                  <span style={{ fontSize: 12, fontWeight: 700, color: '#0F172A' }}>
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
                  <span style={{ fontFamily: 'monospace', color: '#0F172A' }}>{ep.src_ip} → {ep.dst_ip}</span>
                </div>
                {det.src_port && (
                  <div>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>Ports: </span>
                    <span style={{ fontFamily: 'monospace', color: '#0F172A' }}>{det.src_port} → {det.dst_port}</span>
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
                    <span style={{ fontFamily: 'monospace', color: '#0F172A' }}>{det.esp_seq}</span>
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
                    <span style={{ fontFamily: 'monospace', color: '#0F172A' }}>{det.ike_msg_id}</span>
                  </div>
                )}
                {det.layers && det.layers.length > 0 && (
                  <div style={{ gridColumn: '1 / -1' }}>
                    <span style={{ color: '#64748B', fontWeight: 600 }}>Protocol Layer Stack: </span>
                    <span style={{ color: '#0F172A', fontWeight: 600 }}>{det.layers.join(' ➔ ')}</span>
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
        <span style={{ fontSize: 14, fontWeight: 700, color: '#0F172A' }}>{title}</span>
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
          <h1 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#0F172A', marginBottom: 4 }}>Analysis Report</h1>
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

      {/* ── Row 1: Protocol Summary + Risk Score ──────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem', alignItems: 'start' }}>
        {/* Protocol summary */}
        <div className="card" style={{ padding: '1.25rem' }}>
          <SectionHead icon={Layers} title="Protocol Summary" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.625rem' }}>
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
          {m?.vpn_mode_inferred?.includes('Inferred') && (
            <div className="alert-warn" style={{ marginTop: '0.875rem' }}>
              <AlertCircle style={{ width: 13, height: 13, color: '#B45309', flexShrink: 0, marginTop: 1 }} />
              <p style={{ fontSize: 11, color: '#92400E' }}>
                VPN Mode is inferred from observable packet characteristics, not definitively determined.
              </p>
            </div>
          )}
        </div>

        {/* Risk Score */}
        <div style={{
          borderRadius: 14, border: `1px solid ${riskAccent.border}`,
          backgroundColor: riskAccent.bg, padding: '1.5rem',
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          textAlign: 'center', gap: '0.5rem',
        }}>
          <p style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#64748B' }}>Overall Risk</p>
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

      {/* ── Row 2: Cryptographic Parameters ───────────────────────────── */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <SectionHead icon={Lock} title="Cryptographic Parameters" />
        <CryptoRow label="Encryption Algorithm"   value={m?.encryption} />
        <CryptoRow label="Key Exchange (DH Group)" value={m?.key_exchange} />
        <CryptoRow label="Authentication Method"   value={m?.authentication} />
        <p style={{ fontSize: 11, color: '#94A3B8', marginTop: 12, paddingTop: 12, borderTop: '1px solid #F1F5F9', lineHeight: 1.65 }}>
          Values marked "Not Extracted" were not observable. IKE negotiation parameters are only visible if
          the IKE_SA_INIT exchange is present in the capture.
        </p>
      </div>

      {/* ── Feature 3: Evidence-Based Security Findings ───────────────── */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <SectionHead
          icon={AlertTriangle}
          title="Evidence-Based Security Findings"
          action={<span style={{ fontSize: 12, color: '#94A3B8' }}>{sa?.findings?.length ?? 0} finding{sa?.findings?.length !== 1 ? 's' : ''}</span>}
        />

        {sa?.overall_risk_score === 0 && (
          <div className="alert-warn" style={{ marginBottom: '1rem' }}>
            <AlertCircle style={{ width: 13, height: 13, color: '#B45309', flexShrink: 0, marginTop: 1 }} />
            <div>
              <p style={{ fontSize: 12, fontWeight: 600, color: '#92400E', marginBottom: 2 }}>
                Risk Score 0 — does not mean the VPN is fully secure
              </p>
              <p style={{ fontSize: 11, color: '#B45309', lineHeight: 1.6 }}>
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.875rem' }}>
            {highF.map((f, i) => <FindingCard key={i} f={f} />)}
            {infoF.length > 0 && (
              <>
                <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginTop: 8 }}>
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

      {/* ── Feature 1: ML Traffic Classification & Insights ──────────── */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <SectionHead icon={Cpu} title="ML Confidence + Traffic Insights" />
        <MLSection
          ml={ml}
          distribution={m?.packet_size_distribution}
          stats={m?.packet_size_stats}
        />
      </div>

      {/* ── Feature 2: Packet-Level Forensics ─────────────────────────── */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <SectionHead icon={Binary} title="Packet-Level Forensics" />
        <PacketForensicsTable
          packets={m?.packets}
          totalCount={m?.packet_count}
        />
      </div>

    </div>
  );
}
