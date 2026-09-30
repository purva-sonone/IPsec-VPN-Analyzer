import { useState, useEffect } from 'react';
import { useParams, useLocation, useNavigate } from 'react-router-dom';
import {
  ArrowLeft, Download, Shield, Activity, Lock, Key, Wifi,
  AlertTriangle, CheckCircle, XCircle, Info, Cpu, FlaskConical,
  SkipForward, ListChecks, AlertCircle, Layers, RefreshCw,
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate, riskColor, sevColor, strengthOf } from '../lib/utils';

// ── Severity icon map ──────────────────────────────────────────────────────
const SEV_ICON = {
  Critical:      <XCircle       style={{ width: 14, height: 14, color: '#B91C1C', flexShrink: 0 }} />,
  High:          <AlertTriangle style={{ width: 14, height: 14, color: '#DC2626', flexShrink: 0 }} />,
  Medium:        <AlertTriangle style={{ width: 14, height: 14, color: '#D97706', flexShrink: 0 }} />,
  Low:           <Info          style={{ width: 14, height: 14, color: '#2563EB', flexShrink: 0 }} />,
  Informational: <CheckCircle   style={{ width: 14, height: 14, color: '#16A34A', flexShrink: 0 }} />,
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

// ── FindingCard ────────────────────────────────────────────────────────────
function FindingCard({ f }) {
  const sc = sevColor(f.severity);

  // Map severity to border-left color
  const accentColor =
    f.severity === 'High' || f.severity === 'Critical' ? '#DC2626' :
    f.severity === 'Medium' ? '#D97706' :
    f.severity === 'Low' ? '#2563EB' : '#16A34A';

  return (
    <div style={{
      borderRadius: 10, border: '1px solid #E2E8F0',
      borderLeft: `3px solid ${accentColor}`,
      backgroundColor: '#FFFFFF', padding: '1rem',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8, marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          {SEV_ICON[f.severity] || SEV_ICON.Informational}
          <span style={{ fontSize: 13, fontWeight: 600, color: '#0F172A' }}>{f.title}</span>
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
      <p style={{ fontSize: 12, color: '#64748B', lineHeight: 1.65, marginBottom: 8 }}>{f.description}</p>
      <div style={{ fontSize: 11, lineHeight: 1.6 }}>
        {f.evidence && (
          <p style={{ marginBottom: 3 }}>
            <span style={{ fontWeight: 600, color: '#94A3B8' }}>Evidence: </span>
            <span style={{ color: '#475569' }}>{f.evidence}</span>
          </p>
        )}
        {f.recommendation && (
          <p>
            <span style={{ fontWeight: 600, color: '#94A3B8' }}>Recommendation: </span>
            <span style={{ color: '#475569' }}>{f.recommendation}</span>
          </p>
        )}
      </div>
    </div>
  );
}

// ── Rule Audit ─────────────────────────────────────────────────────────────
function RuleAudit({ evaluated = [], skipped = [] }) {
  if (evaluated.length === 0 && skipped.length === 0) return null;
  return (
    <div style={{ marginTop: '1.25rem', borderRadius: 10, border: '1px solid #E2E8F0', backgroundColor: '#FFFFFF', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '0.625rem 1rem', borderBottom: '1px solid #E2E8F0', backgroundColor: '#F8FAFC' }}>
        <ListChecks style={{ width: 12, height: 12, color: '#94A3B8' }} />
        <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8' }}>Rule Audit</span>
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
            const isFail = r.status === 'FAIL';
            return (
              <tr key={`ev-${i}`} style={{ borderBottom: '1px solid #F8FAFC' }}>
                <td style={{ padding: '0.625rem 0.875rem', fontWeight: 500, color: '#0F172A' }}>{r.rule}</td>
                <td style={{ padding: '0.625rem 0.875rem', color: '#475569', fontFamily: 'monospace' }}>{r.observed_value || '—'}</td>
                <td style={{ padding: '0.625rem 0.875rem' }}>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontWeight: 600, fontSize: 11, color: isFail ? '#B91C1C' : '#15803D' }}>
                    {isFail ? <XCircle style={{ width: 11, height: 11 }} /> : <CheckCircle style={{ width: 11, height: 11 }} />}
                    {r.status || 'PASS'}
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

// ── ML Section ─────────────────────────────────────────────────────────────
const ML_COLORS = { C2: '#DC2626', CHAT: '#2563EB', FILE_TRANSFER: '#16A34A', STREAMING: '#D97706', VOIP: '#7C3AED' };

function MLSection({ ml }) {
  if (!ml) return null;
  const { model_status, model_note, predicted_category, confidence_score,
          features_available = [], all_class_probabilities, dataset_note } = ml;

  if (model_status === 'not_applicable') {
    return (
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '0.875rem 1rem', borderRadius: 8, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
        <AlertCircle style={{ width: 14, height: 14, color: '#94A3B8', flexShrink: 0, marginTop: 1 }} />
        <div>
          <p style={{ fontSize: 13, fontWeight: 600, color: '#64748B', marginBottom: 3 }}>Not Applicable</p>
          <p style={{ fontSize: 12, color: '#94A3B8', lineHeight: 1.6 }}>{model_note}</p>
        </div>
      </div>
    );
  }

  if (model_status !== 'trained_model') {
    return <p style={{ fontSize: 13, color: '#64748B' }}>{model_note}</p>;
  }

  const conf     = confidence_score != null ? (confidence_score * 100).toFixed(1) : null;
  const probaArr = all_class_probabilities
    ? Object.entries(all_class_probabilities)
        .map(([name, value]) => ({ name, value: parseFloat((value * 100).toFixed(1)) }))
        .sort((a, b) => b.value - a.value)
    : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      {/* Model note */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, padding: '0.75rem 0.875rem', borderRadius: 8, backgroundColor: '#F5F3FF', border: '1px solid #DDD6FE' }}>
        <FlaskConical style={{ width: 13, height: 13, color: '#7C3AED', flexShrink: 0, marginTop: 1 }} />
        <p style={{ fontSize: 11, color: '#6D28D9', lineHeight: 1.65 }}>
          <strong>ML Traffic Classifier Active.</strong>{' '}
          {dataset_note || 'RandomForestClassifier trained on VNAT Feature Dataframe.'}
        </p>
      </div>

      {/* Prediction block */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '1.25rem', borderRadius: 10, backgroundColor: '#F8FAFC', border: '1px solid #E2E8F0' }}>
        <div>
          <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginBottom: 6 }}>Predicted Category</p>
          <p style={{ fontSize: '1.75rem', fontWeight: 700, color: '#6D28D9' }}>{predicted_category}</p>
        </div>
        <div style={{ textAlign: 'right' }}>
          <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginBottom: 6 }}>Confidence</p>
          <p style={{ fontSize: '1.75rem', fontWeight: 700, color: '#0F172A' }}>{conf != null ? `${conf}%` : 'N/A'}</p>
        </div>
      </div>

      {/* Category probabilities */}
      {probaArr.length > 0 && (
        <div style={{ borderRadius: 8, border: '1px solid #E2E8F0', overflow: 'hidden' }}>
          <p style={{ padding: '0.5rem 0.875rem', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', borderBottom: '1px solid #F1F5F9', backgroundColor: '#F8FAFC' }}>
            Category Probabilities
          </p>
          <div style={{ padding: '0.75rem', display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.625rem' }}>
            {probaArr.map(d => (
              <div key={d.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '0.5rem', borderBottom: '1px solid #F1F5F9' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: ML_COLORS[d.name] || '#94A3B8', flexShrink: 0 }} />
                  <span style={{ fontSize: 12, fontWeight: 500, color: '#475569' }}>{d.name}</span>
                </div>
                <span style={{ fontSize: 12, color: '#94A3B8', fontVariantNumeric: 'tabular-nums' }}>{d.value}%</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Explanatory note */}
      <p style={{ fontSize: 11, color: '#94A3B8', lineHeight: 1.65, borderLeft: '2px solid #DDD6FE', paddingLeft: '0.75rem' }}>{model_note}</p>

      {/* Features used */}
      {features_available.length > 0 && (
        <div style={{ borderRadius: 8, border: '1px solid #E2E8F0', overflow: 'hidden' }}>
          <p style={{ padding: '0.5rem 0.875rem', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', borderBottom: '1px solid #F1F5F9', backgroundColor: '#F8FAFC' }}>
            Features Used
          </p>
          <div style={{ padding: '0.75rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.375rem' }}>
            {features_available.map((f, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <CheckCircle style={{ width: 10, height: 10, color: '#16A34A', flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: '#64748B' }}>{f}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Section Header ─────────────────────────────────────────────────────────
function SectionHead({ icon: Icon, title, action }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon style={{ width: 15, height: 15, color: '#2563EB' }} />
        <span style={{ fontSize: 14, fontWeight: 600, color: '#0F172A' }}>{title}</span>
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
            <p style={{ fontSize: 11, color: '#64748B', lineHeight: 1.65, marginTop: 4, maxWidth: 200 }}>
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

      {/* ── Row 3: Security Findings ────────────────────────────────────── */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <SectionHead
          icon={AlertTriangle}
          title="Security Findings"
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
            {highF.map((f, i) => <FindingCard key={i} f={f} />)}
            {infoF.length > 0 && (
              <>
                <p style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.07em', color: '#94A3B8', marginTop: 8 }}>
                  Informational
                </p>
                {infoF.map((f, i) => <FindingCard key={`info-${i}`} f={f} />)}
              </>
            )}
          </div>
        )}

        <RuleAudit evaluated={sa?.rules_evaluated} skipped={sa?.rules_skipped} />
      </div>

      {/* ── Row 4: ML Classification ────────────────────────────────────── */}
      <div className="card" style={{ padding: '1.25rem' }}>
        <SectionHead icon={Cpu} title="ML Traffic Classification" />
        <MLSection ml={ml} />
      </div>

    </div>
  );
}
