import { useLocation, useNavigate } from 'react-router-dom';
import {
  Shield, Activity, Lock, Key, ArrowLeft, AlertTriangle,
  CheckCircle, Info, XCircle, Cpu,
  Layers, Wifi, AlertCircle, FlaskConical,
  SkipForward, ListChecks
} from 'lucide-react';

// ── Severity colour config ────────────────────────────────────────────────────
const SEV = {
  Critical:      { badge: 'bg-red-500/20 text-red-300 border-red-500/40',         icon: <XCircle       className="w-4 h-4 text-red-600 shrink-0"    />, bar: 'bg-red-500'    },
  High:          { badge: 'bg-orange-500/20 text-orange-300 border-orange-500/40', icon: <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />, bar: 'bg-orange-500' },
  Medium:        { badge: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40', icon: <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0" />, bar: 'bg-yellow-500' },
  Low:           { badge: 'bg-blue-500/20 text-blue-300 border-blue-500/40',       icon: <Info          className="w-4 h-4 text-blue-400 shrink-0"    />, bar: 'bg-blue-500'   },
  Informational: { badge: 'bg-slate-500/20 text-slate-300 border-slate-500/40',    icon: <CheckCircle   className="w-4 h-4 text-slate-400 shrink-0"   />, bar: 'bg-slate-500'  },
};

// ── Risk level colour config ──────────────────────────────────────────────────
const RISK_COLOR = {
  High:          { text: 'text-orange-400',  bg: 'bg-orange-500/10',  border: 'border-orange-500/30'  },
  Medium:        { text: 'text-yellow-400',  bg: 'bg-yellow-500/10',  border: 'border-yellow-500/30'  },
  Low:           { text: 'text-emerald-600', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
  Informational: { text: 'text-slate-400',   bg: 'bg-slate-500/10',   border: 'border-slate-500/30'   },
};

// ── Helper: strength badge for a crypto parameter ─────────────────────────────
function StrengthBadge({ value }) {
  if (!value || value === 'Not Extracted' || value === 'Unknown' || value === 'Not Available') {
    return <span className="text-xs px-2 py-0.5 rounded-full bg-slate-200 text-slate-400 border border-slate-600">Not Extracted</span>;
  }
  const WEAK   = ['DES', '3DES', 'RC4', 'RC5', 'NULL', 'Blowfish', 'Group 1', 'Group 2', 'Group 5', 'IKEv1', 'IDEA', 'CAST', 'MD5'];
  const STRONG = ['AES-GCM', 'AES-CCM', 'ChaCha20', 'Group 14', 'Group 19', 'Group 20', 'Group 21', 'Group 31', 'ECDSA', 'SHA-256', 'SHA-384', 'SHA-512', 'IKEv2'];
  if (STRONG.some(s => value.includes(s))) return <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">✓ Strong</span>;
  if (WEAK.some(w   => value.includes(w))) return <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/15 text-red-300 border border-red-500/30">⚠ Weak</span>;
  return <span className="text-xs px-2 py-0.5 rounded-full bg-indigo-500/15 text-indigo-700 border border-indigo-500/30">Observed</span>;
}

// ── MetricCard ────────────────────────────────────────────────────────────────
function MetricCard({ label, value, icon }) {
  const isEmpty = !value || value === 'Not Extracted' || value === 'Unknown' || value === 'Not Available';
  return (
    <div className="bg-slate-100/60 border border-slate-300/60 rounded-xl p-4 flex flex-col gap-1">
      <div className="flex items-center gap-1.5 text-slate-400 text-xs font-medium mb-1">
        {icon}
        {label}
      </div>
      <p className={`font-semibold text-sm leading-snug ${isEmpty ? 'text-slate-400 italic' : 'text-slate-900'}`}>
        {isEmpty ? 'Not Extracted' : value}
      </p>
    </div>
  );
}

// ── CryptoRow ─────────────────────────────────────────────────────────────────
function CryptoRow({ label, value }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-slate-300/50 last:border-0">
      <span className="text-slate-400 text-sm">{label}</span>
      <div className="flex items-center gap-2 text-right">
        <span className={`text-sm font-medium max-w-xs truncate ${(!value || value === 'Not Extracted' || value === 'Unknown') ? 'text-slate-400 italic' : 'text-slate-800'}`}>
          {(!value || value === 'Not Extracted' || value === 'Unknown') ? 'Not Extracted' : value}
        </span>
        <StrengthBadge value={value} />
      </div>
    </div>
  );
}

// ── FindingCard ───────────────────────────────────────────────────────────────
function FindingCard({ finding }) {
  const cfg = SEV[finding.severity] || SEV.Informational;
  return (
    <div className="rounded-xl border bg-slate-100/40 border-slate-300/60 p-5 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          {cfg.icon}
          <span className="font-semibold text-slate-900 text-sm">{finding.title}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {finding.risk_contribution > 0 && (
            <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-red-500/15 text-red-300 border border-red-500/30">
              +{finding.risk_contribution} risk
            </span>
          )}
          <span className={`text-xs font-medium px-2.5 py-1 rounded-full border ${cfg.badge}`}>
            {finding.severity}
          </span>
        </div>
      </div>
      <p className="text-slate-400 text-sm leading-relaxed">{finding.description}</p>
      <div className="space-y-1.5 text-xs">
        <p><span className="text-slate-400 font-medium">Evidence: </span><span className="text-slate-300">{finding.evidence}</span></p>
        <p><span className="text-slate-400 font-medium">Recommendation: </span><span className="text-slate-300">{finding.recommendation}</span></p>
      </div>
    </div>
  );
}

// ── RulesAuditPanel ───────────────────────────────────────────────────────────
function RulesAuditPanel({ rulesEvaluated = [], rulesSkipped = [] }) {
  if (rulesEvaluated.length === 0 && rulesSkipped.length === 0) return null;
  return (
    <div className="mt-4 rounded-xl border border-slate-300/60 bg-slate-100/30 overflow-hidden">
      <div className="px-4 py-2.5 border-b border-slate-300/40 flex items-center gap-2">
        <ListChecks className="w-3.5 h-3.5 text-slate-400" />
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Rule Audit</span>
      </div>
      <div className="divide-y divide-slate-700/30">
        {rulesEvaluated.map((r, i) => (
          <div key={`ev-${i}`} className="px-4 py-2.5 flex items-start gap-3">
            <CheckCircle className="w-3.5 h-3.5 text-emerald-600 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-medium text-slate-300">{r.rule}</p>
              {r.observed_value && (
                <p className="text-xs text-slate-400 mt-0.5">
                  Observed: <span className="text-slate-400 font-mono">{r.observed_value}</span>
                </p>
              )}
            </div>
          </div>
        ))}
        {rulesSkipped.map((r, i) => (
          <div key={`sk-${i}`} className="px-4 py-2.5 flex items-start gap-3">
            <SkipForward className="w-3.5 h-3.5 text-amber-600/70 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-medium text-slate-400">{r.rule} <span className="text-amber-600/70">(skipped)</span></p>
              {r.reason && <p className="text-xs text-slate-400 mt-0.5">{r.reason}</p>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── TrafficClassification ─────────────────────────────────────────────────────
function TrafficClassification({ ml }) {
  if (!ml) return null;

  const { model_status, model_note, predicted_category, confidence_score,
          features_available = [], features_required_missing = [],
          all_class_probabilities, dataset_note } = ml;

  // Case A: Not applicable (no ESP)
  if (model_status === 'not_applicable') {
    return (
      <div className="flex items-start gap-3 rounded-xl px-4 py-3 bg-slate-200/40 border border-slate-600/50">
        <AlertCircle className="w-5 h-5 text-slate-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-semibold text-slate-300">Not Applicable</p>
          <p className="text-xs text-slate-400 leading-relaxed mt-1">{model_note}</p>
        </div>
      </div>
    );
  }

  // Case B: Fallback (model unavailable, insufficient features, etc.)
  if (model_status !== 'trained_model') {
    return (
      <div className="space-y-4">

        {/* Status row */}
        <div className="flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-xs mb-1">Classification Status</p>
            <p className={`text-lg font-semibold ${predicted_category === 'Unknown' ? 'text-slate-400 italic' : 'text-slate-900'}`}>
              {predicted_category}
            </p>
          </div>
          <div className="text-right">
            <p className="text-slate-400 text-xs mb-1">Confidence</p>
            <p className="text-slate-400 text-sm font-medium italic">
              {confidence_score !== null && confidence_score !== undefined
                ? `${(confidence_score * 100).toFixed(1)}%`
                : 'N/A'}
            </p>
          </div>
        </div>

        {/* Explanation */}
        <p className="text-slate-400 text-xs leading-relaxed border-l-2 border-amber-500/40 pl-3">
          {model_note}
        </p>

        {/* Feature availability breakdown */}
        {(features_available.length > 0 || features_required_missing.length > 0) && (
          <div className="rounded-xl border border-slate-300/60 bg-slate-100/30 overflow-hidden">
            <div className="px-4 py-2.5 border-b border-slate-300/40">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Feature Availability</span>
            </div>
            <div className="p-3 space-y-1.5">
              {features_available.map((f, i) => (
                <div key={`av-${i}`} className="flex items-center gap-2 text-xs">
                  <CheckCircle className="w-3 h-3 text-emerald-600 shrink-0" />
                  <span className="text-slate-400">{f}</span>
                  <span className="ml-auto text-emerald-600/70 font-medium">Available</span>
                </div>
              ))}
              {features_required_missing.map((f, i) => (
                <div key={`ms-${i}`} className="flex items-center gap-2 text-xs">
                  <XCircle className="w-3 h-3 text-red-600/70 shrink-0" />
                  <span className="text-slate-400">{f}</span>
                  <span className="ml-auto text-red-600/50 font-medium">Not Extracted</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  // Case C: Trained Model Prediction
  return (
    <div className="space-y-4">
      {/* Trained Model Badge */}
      <div className="flex items-start gap-2 rounded-lg px-3 py-2.5 bg-indigo-500/10 border border-indigo-500/30">
        <FlaskConical className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
        <p className="text-xs text-indigo-200 leading-relaxed">
          <span className="font-semibold text-indigo-700">ML Traffic Classifier Active.</span>{' '}
          {dataset_note || 'Predicts traffic category based on flow characteristics.'}
        </p>
      </div>

      {/* Status row */}
      <div className="flex items-center justify-between bg-slate-100/60 border border-slate-300/60 rounded-xl p-5">
        <div>
          <p className="text-slate-400 text-xs font-medium mb-1 uppercase tracking-wider">Predicted Category</p>
          <p className="text-2xl font-bold text-emerald-600">
            {predicted_category}
          </p>
        </div>
        <div className="text-right">
          <p className="text-slate-400 text-xs font-medium mb-1 uppercase tracking-wider">Confidence</p>
          <p className="text-xl font-bold text-slate-800">
            {confidence_score !== null && confidence_score !== undefined
              ? `${(confidence_score * 100).toFixed(1)}%`
              : 'N/A'}
          </p>
        </div>
      </div>

      {/* Class Probabilities */}
      {all_class_probabilities && (
        <div className="space-y-2 mt-4">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Category Probabilities</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {Object.entries(all_class_probabilities).sort((a,b) => b[1] - a[1]).map(([cls, prob]) => (
              <div key={cls} className="flex items-center justify-between text-xs bg-slate-100/40 border border-slate-300/40 p-2 rounded-lg">
                <span className="text-slate-300 font-medium">{cls}</span>
                <span className="text-slate-400">{(prob * 100).toFixed(1)}%</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Explanation */}
      <p className="text-slate-400 text-xs leading-relaxed border-l-2 border-indigo-500/40 pl-3 mt-4">
        {model_note}
      </p>

      {/* Feature availability breakdown */}
      {(features_available.length > 0 || features_required_missing.length > 0) && (
        <div className="rounded-xl border border-slate-300/60 bg-slate-100/30 overflow-hidden mt-4">
          <div className="px-4 py-2.5 border-b border-slate-300/40">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Features Used for Prediction</span>
          </div>
          <div className="p-3 space-y-1.5">
            {features_available.map((f, i) => (
              <div key={`av-${i}`} className="flex items-center gap-2 text-xs">
                <CheckCircle className="w-3 h-3 text-emerald-600 shrink-0" />
                <span className="text-slate-400">{f}</span>
              </div>
            ))}
            {features_required_missing.map((f, i) => (
              <div key={`ms-${i}`} className="flex items-center gap-2 text-xs">
                <XCircle className="w-3 h-3 text-red-600/70 shrink-0" />
                <span className="text-slate-400">{f}</span>
                <span className="ml-auto text-red-600/50 font-medium">Not Extracted</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main Results Page ─────────────────────────────────────────────────────────
export default function Results() {
  const location = useLocation();
  const navigate = useNavigate();
  const result = location.state?.result;

  // Guard: no data passed
  if (!result) {
    return (
      <div className="w-full max-w-3xl mx-auto flex flex-col items-center justify-center py-24 space-y-4">
        <Shield className="w-12 h-12 text-slate-500" />
        <p className="text-slate-400 text-lg">No analysis results found.</p>
        <button
          onClick={() => navigate('/upload')}
          className="mt-2 px-5 py-2 bg-indigo-500 hover:bg-indigo-600 text-white rounded-lg text-sm font-medium transition-colors"
        >
          Upload a PCAP file
        </button>
      </div>
    );
  }

  const { filename, pcap_metrics: m, security_assessment: sa, ml_prediction: ml } = result;
  const riskCfg = RISK_COLOR[sa?.risk_level] || RISK_COLOR.Informational;

  // Separate high-severity findings from informational ones
  const highFindings = (sa?.findings || []).filter(f => ['Critical','High','Medium','Low'].includes(f.severity));
  const infoFindings = (sa?.findings || []).filter(f => f.severity === 'Informational');

  const rulesEvaluated = sa?.rules_evaluated || [];
  const rulesSkipped   = sa?.rules_skipped   || [];

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6 pb-12">

      {/* ── Header ── */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate('/upload')}
          className="flex items-center gap-2 text-slate-400 hover:text-slate-800 text-sm transition-colors"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Upload
        </button>
        <div className="text-right">
          <p className="text-slate-400 text-xs">Analyzed file</p>
          <p className="text-slate-800 text-sm font-medium truncate max-w-xs">{filename}</p>
        </div>
      </div>

      {/* ── Row 1: Protocol Summary + Risk Score ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Protocol Summary */}
        <div className="lg:col-span-2 bg-slate-100 backdrop-blur border border-slate-300 rounded-2xl p-6 space-y-4">
          <h3 className="text-base font-semibold flex items-center gap-2 text-slate-800">
            <Layers className="w-5 h-5 text-indigo-600" /> Protocol Summary
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <MetricCard label="Packet Count"  value={String(m?.packet_count ?? '—')} icon={<Activity className="w-3 h-3"/>} />
            <MetricCard label="IKE Version"   value={m?.ike_version}                  icon={<Key className="w-3 h-3"/>} />
            <MetricCard label="Protocols"     value={m?.protocols_found?.join(', ')}   icon={<Wifi className="w-3 h-3"/>} />
            <MetricCard label="VPN Mode"      value={m?.vpn_mode_inferred}             icon={<Shield className="w-3 h-3"/>} />
          </div>
          {m?.vpn_mode_inferred?.includes('Inferred') && (
            <p className="text-xs text-amber-600/80 bg-amber-500/10 border border-amber-500/20 rounded-lg px-3 py-2">
              ⓘ VPN Mode is an inference based on observable packet characteristics, not a definitive determination.
            </p>
          )}
        </div>

        {/* Risk Score */}
        <div className={`rounded-2xl border p-6 flex flex-col items-center justify-center space-y-3 ${riskCfg.bg} ${riskCfg.border}`}>
          <p className="text-slate-400 text-sm font-medium">Overall Risk</p>
          <div className={`text-5xl font-extrabold ${riskCfg.text}`}>
            {sa?.overall_risk_score ?? 0}
          </div>
          <span className={`text-sm font-semibold px-3 py-1 rounded-full border ${riskCfg.bg} ${riskCfg.border} ${riskCfg.text}`}>
            {sa?.risk_level ?? 'Unknown'}
          </span>
          {sa?.score_explanation && (
            <p className="text-slate-400 text-xs text-center leading-relaxed pt-1">{sa.score_explanation}</p>
          )}
        </div>
      </div>

      {/* ── Row 2: Cryptographic Parameters ── */}
      <div className="bg-slate-100 backdrop-blur border border-slate-300 rounded-2xl p-6">
        <h3 className="text-base font-semibold flex items-center gap-2 text-slate-800 mb-4">
          <Lock className="w-5 h-5 text-indigo-600" /> Cryptographic Parameters
        </h3>
        <CryptoRow label="Encryption Algorithm"   value={m?.encryption} />
        <CryptoRow label="Key Exchange (DH Group)" value={m?.key_exchange} />
        <CryptoRow label="Authentication Method"   value={m?.authentication} />
        <p className="text-xs text-slate-500 mt-3 pt-3 border-t border-slate-300/50">
          Values marked "Not Extracted" were not observable in the captured packets. IKE negotiation parameters
          are only visible if the IKE_SA_INIT exchange is present in the capture.
        </p>
      </div>

      {/* ── Row 3: Security Findings ── */}
      <div className="bg-slate-100 backdrop-blur border border-slate-300 rounded-2xl p-6 space-y-4">
        <h3 className="text-base font-semibold flex items-center gap-2 text-slate-800">
          <AlertTriangle className="w-5 h-5 text-indigo-600" /> Security Findings
          <span className="ml-auto text-xs text-slate-400 font-normal">
            {(sa?.findings?.length ?? 0)} finding{(sa?.findings?.length ?? 0) !== 1 ? 's' : ''}
          </span>
        </h3>

        {/* Risk score 0 with skipped rules callout */}
        {sa?.overall_risk_score === 0 && (
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 px-4 py-3 flex items-start gap-3">
            <AlertCircle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
            <div className="text-xs text-amber-300/80 leading-relaxed space-y-1">
              <p className="font-semibold text-amber-300">Risk Score 0 — does not mean the VPN is fully secure</p>
              <p>
                A score of 0 means no high-risk values were found <em>among the parameters that could be extracted</em>.{' '}
                {rulesSkipped.length > 0
                  ? `${rulesSkipped.length} rule(s) were skipped because the required parameters were not visible in this capture (see Rule Audit below).`
                  : 'All observable parameters passed the security checks.'}
              </p>
            </div>
          </div>
        )}

        {sa?.findings?.length === 0 ? (
          <p className="text-slate-400 text-sm py-4 text-center">
            No security findings — no observable parameters to evaluate.
          </p>
        ) : (
          <div className="space-y-3">
            {/* High priority findings first */}
            {highFindings.map((f, i) => <FindingCard key={i} finding={f} />)}
            {/* Informational findings collapsed/secondary */}
            {infoFindings.length > 0 && (
              <>
                <p className="text-xs text-slate-400 font-medium uppercase tracking-wider pt-1">
                  Informational
                </p>
                {infoFindings.map((f, i) => <FindingCard key={`info-${i}`} finding={f} />)}
              </>
            )}
          </div>
        )}

        {/* Rule audit showing what ran and what was skipped */}
        <RulesAuditPanel rulesEvaluated={rulesEvaluated} rulesSkipped={rulesSkipped} />
      </div>

      {/* ── Row 4: Traffic Classification ── */}
      <div className="bg-slate-100 backdrop-blur border border-slate-300 rounded-2xl p-6">
        <h3 className="text-base font-semibold flex items-center gap-2 text-slate-800 mb-4">
          <Cpu className="w-5 h-5 text-indigo-600" /> Traffic Classification
        </h3>
        <TrafficClassification ml={ml} />
      </div>

    </div>
  );
}
