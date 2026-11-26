import { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Sparkles, Shield, AlertTriangle, Activity,
  Cpu, Info, ArrowRight, Loader2,
  XCircle, HelpCircle, Zap, ChevronDown, Layers, CheckCircle2,
} from 'lucide-react';
import { api } from '../lib/api';
import { fmtDate, sevColor } from '../lib/utils';

// ─────────────────────────────────────────────────────────────
// Constants & Helpers
// ─────────────────────────────────────────────────────────────
const SEV_WEIGHT = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Informational: 0,
};

function sevRank(sev) {
  return SEV_WEIGHT[sev] ?? 0;
}

function SectionHeader({ icon: Icon, label, subtitle, color = 'var(--blue)', bg = 'var(--blue-light)', border = 'var(--blue-border)', right }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: '0.75rem', flexWrap: 'wrap' }}>
      <div style={{
        width: 30, height: 30, borderRadius: 8,
        backgroundColor: bg, border: `1px solid ${border}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
      }}>
        <Icon size={15} style={{ color }} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <h2 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{label}</h2>
        {subtitle && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{subtitle}</div>
        )}
      </div>
      {right}
    </div>
  );
}

function Card({ children, style = {} }) {
  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 10, padding: '1rem 1.25rem',
      ...style,
    }}>
      {children}
    </div>
  );
}

function ObsBadge({ type }) {
  const isObs = type === 'Observed';
  return (
    <span style={{
      fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 9999,
      backgroundColor: isObs ? 'var(--blue-light)' : 'var(--yellow-light)',
      color: isObs ? 'var(--blue)' : 'var(--yellow-text)',
      border: `1px solid ${isObs ? 'var(--blue-border)' : 'var(--yellow-border)'}`,
    }}>
      {type ?? 'Unknown'}
    </span>
  );
}

function InfoNote({ children }) {
  return (
    <div style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 7, padding: '0.5rem 0.75rem',
      fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5,
      display: 'flex', gap: 6,
    }}>
      <Info size={12} style={{ flexShrink: 0, marginTop: 1 }} />
      <div>{children}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Main component
// ─────────────────────────────────────────────────────────────
export default function AdvisorPage() {
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Collapsible / view-more toggles
  const [showAllPriority, setShowAllPriority] = useState(false);
  const [showAllML, setShowAllML] = useState(false);
  const [showRiskDetails, setShowRiskDetails] = useState(false);
  const [showNormalBeaconing, setShowNormalBeaconing] = useState(false);

  useEffect(() => {
    setLoading(true);
    api.findings()
      .then((d) => setData(d))
      .catch((e) => setError(e?.message ?? 'Failed to load advisor context.'))
      .finally(() => setLoading(false));
  }, []);

  const ctx = data?.advisor_context ?? {};
  const findings = data?.findings ?? [];
  const anomalies = data?.anomalies ?? [];
  const count = ctx.analyses_count ?? 0;
  const riskSummaries = ctx.risk_summaries ?? [];
  const skipped = ctx.skipped_rules ?? [];
  const mlExplanations = ctx.ml_explanations ?? [];
  const beaconingSummaries = ctx.beaconing_summaries ?? [];

  // 1. Priority Actions: actionable findings sorted by severity + risk contribution
  const priorityActions = useMemo(() => {
    return findings
      .filter((f) => f.status === 'Action Required' || (f.risk_contribution ?? 0) > 0 || sevRank(f.severity) >= 1)
      .slice()
      .sort((a, b) => {
        const sDiff = sevRank(b.severity) - sevRank(a.severity);
        if (sDiff !== 0) return sDiff;
        const rDiff = (b.risk_contribution ?? 0) - (a.risk_contribution ?? 0);
        if (rDiff !== 0) return rDiff;
        return new Date(b.created_at ?? 0).getTime() - new Date(a.created_at ?? 0).getTime();
      });
  }, [findings]);

  // 2. Consolidated Security Insights: group identical rule findings across sessions
  const consolidatedInsights = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      const key = `${f.title ?? ''}||${f.severity ?? ''}||${f.affected_parameter ?? ''}`;
      if (!map.has(key)) {
        map.set(key, {
          key,
          title: f.title,
          severity: f.severity,
          status: f.status,
          observation_type: f.observation_type,
          affected_parameter: f.affected_parameter,
          description: f.description,
          recommendation: f.recommendation,
          maxRisk: f.risk_contribution ?? 0,
          occurrences: 0,
          analyses: new Map(),
        });
      }
      const entry = map.get(key);
      entry.occurrences += 1;
      if ((f.risk_contribution ?? 0) > entry.maxRisk) {
        entry.maxRisk = f.risk_contribution ?? 0;
      }
      if (f.analysis_id && !entry.analyses.has(f.analysis_id)) {
        entry.analyses.set(f.analysis_id, {
          analysis_id: f.analysis_id,
          filename: f.filename || f.analysis_id,
          finding_id: f.finding_id,
          created_at: f.created_at,
        });
      }
    }
    return Array.from(map.values())
      .map((item) => ({ ...item, analyses: Array.from(item.analyses.values()) }))
      .sort((a, b) => {
        const sDiff = sevRank(b.severity) - sevRank(a.severity);
        if (sDiff !== 0) return sDiff;
        return b.occurrences - a.occurrences;
      });
  }, [findings]);

  // 5. Recommended Remediation: deduplicate by (recommendation + affected_parameter)
  const remediations = useMemo(() => {
    const map = new Map();
    for (const f of findings) {
      if (!f.recommendation) continue;
      if (f.status !== 'Action Required' && (f.risk_contribution ?? 0) <= 0 && sevRank(f.severity) < 1) {
        continue;
      }
      const key = `${f.recommendation.trim()}||${f.affected_parameter ?? ''}`;
      if (!map.has(key)) {
        map.set(key, {
          key,
          recommendation: f.recommendation,
          affected_parameter: f.affected_parameter || 'General',
          severity: f.severity,
          evidence: f.evidence,
          analyses: new Map(),
        });
      }
      const entry = map.get(key);
      if (sevRank(f.severity) > sevRank(entry.severity)) {
        entry.severity = f.severity;
      }
      if (f.analysis_id && !entry.analyses.has(f.analysis_id)) {
        entry.analyses.set(f.analysis_id, {
          analysis_id: f.analysis_id,
          filename: f.filename || f.analysis_id,
          finding_id: f.finding_id,
        });
      }
    }
    return Array.from(map.values())
      .map((item) => ({ ...item, analyses: Array.from(item.analyses.values()) }))
      .sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  }, [findings]);

  // Consolidated skipped rules
  const consolidatedSkipped = useMemo(() => {
    const map = new Map();
    for (const s of skipped) {
      const ruleName = s.rule_id ?? s.rule ?? 'Unknown rule';
      const reason = s.reason ?? '';
      const key = `${ruleName}||${reason}`;
      if (!map.has(key)) {
        map.set(key, {
          key,
          rule: ruleName,
          parameter: s.parameter,
          reason,
          count: 0,
          analyses: new Map(),
        });
      }
      const entry = map.get(key);
      entry.count += 1;
      if (s.analysis_id && !entry.analyses.has(s.analysis_id)) {
        entry.analyses.set(s.analysis_id, {
          analysis_id: s.analysis_id,
          filename: s.filename || s.analysis_id,
        });
      }
    }
    return Array.from(map.values()).map((item) => ({
      ...item,
      analyses: Array.from(item.analyses.values()),
    }));
  }, [skipped]);

  // Risk summary quick counts
  const riskCounts = useMemo(() => {
    let highCrit = 0;
    let medium = 0;
    let lowInfo = 0;
    for (const r of riskSummaries) {
      const lvl = r.risk_level ?? r.level ?? '';
      if (lvl === 'Critical' || lvl === 'High') highCrit += 1;
      else if (lvl === 'Medium') medium += 1;
      else lowInfo += 1;
    }
    return { highCrit, medium, lowInfo };
  }, [riskSummaries]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '4rem', gap: 10, color: 'var(--text-muted)', fontSize: 13 }}>
      <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} /> Loading advisor context…
    </div>
  );

  if (error) return (
    <div style={{
      padding: '1rem', borderRadius: 10,
      backgroundColor: 'var(--red-light)', border: '1px solid var(--red-border)',
      color: 'var(--red-text)', fontSize: 13, display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <AlertTriangle size={16} /> {error}
    </div>
  );

  if (count === 0) return (
    <EmptyAdvisor onAnalyze={() => navigate('/upload')} />
  );

  const visiblePriority = showAllPriority ? priorityActions : priorityActions.slice(0, 5);
  const visibleML = showAllML ? mlExplanations : mlExplanations.slice(0, 4);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: 960, margin: '0 auto' }}>

      {/* ── Page Header ───────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <div style={{
          width: 36, height: 36, borderRadius: 9,
          backgroundColor: 'var(--blue-light)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid var(--blue-border)', flexShrink: 0,
        }}>
          <Sparkles size={18} style={{ color: 'var(--blue)' }} />
        </div>
        <div style={{ flex: 1, minWidth: 200 }}>
          <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
            AI Security Advisor
          </h1>
          <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)' }}>
            Deterministic rule-based findings, behavioral timing telemetry, and ML traffic insights synthesized across {count} analysis session{count !== 1 ? 's' : ''}.
          </p>
        </div>
      </div>

      {/* ── 1. Priority Actions ───────────────────────────── */}
      <Card>
        <SectionHeader
          icon={Zap}
          label="Priority Actions"
          subtitle="Highest-severity actionable findings ranked by severity and risk contribution"
          color="var(--red)"
          bg="var(--red-light)"
          border="var(--red-border)"
          right={priorityActions.length > 0 && (
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>
              {priorityActions.length} actionable
            </span>
          )}
        />
        {priorityActions.length === 0 ? (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '0.75rem', borderRadius: 8,
            backgroundColor: 'var(--green-light)', border: '1px solid var(--green-border)',
            color: 'var(--green-text)', fontSize: 12,
          }}>
            <CheckCircle2 size={15} />
            <span>No action-required findings detected in the evaluated captures.</span>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
            {visiblePriority.map((f) => (
              <PriorityActionRow
                key={f.finding_id}
                finding={f}
                onNavigate={() => navigate(`/analysis/${f.analysis_id}`)}
              />
            ))}
            {priorityActions.length > 5 && (
              <button
                type="button"
                onClick={() => setShowAllPriority((v) => !v)}
                style={{
                  alignSelf: 'flex-start',
                  background: 'transparent', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '0.35rem 0.75rem',
                  fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', cursor: 'pointer',
                }}
              >
                {showAllPriority ? 'Show top 5' : `Show all ${priorityActions.length} priority actions`}
              </button>
            )}
          </div>
        )}
      </Card>

      {/* ── 2. Consolidated Security Insights ─────────────── */}
      {consolidatedInsights.length > 0 && (
        <Card>
          <SectionHeader
            icon={Layers}
            label="Consolidated Security Insights"
            subtitle="Repeated findings grouped by rule, severity, and affected parameter across sessions"
            color="var(--yellow-text)"
            bg="var(--yellow-light)"
            border="var(--yellow-border)"
            right={
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>
                {consolidatedInsights.length} unique pattern{consolidatedInsights.length !== 1 ? 's' : ''} ({findings.length} total)
              </span>
            }
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {consolidatedInsights.map((group) => (
              <ConsolidatedInsightRow
                key={group.key}
                group={group}
                onNavigateAnalysis={(aid) => navigate(`/analysis/${aid}`)}
              />
            ))}
          </div>
        </Card>
      )}

      {/* ── 3. Behavioral Security Insights ───────────────── */}
      {(anomalies.length > 0 || beaconingSummaries.length > 0) && (
        <Card>
          <SectionHeader
            icon={Activity}
            label="Behavioral Security Insights"
            subtitle="Inter-arrival timing regularity and beaconing telemetry"
            color="var(--red)"
            bg="var(--red-light)"
            border="var(--red-border)"
            right={
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>
                {anomalies.length} anomal{anomalies.length === 1 ? 'y' : 'ies'}
              </span>
            }
          />
          <InfoNote>
            <strong>Observed vs. Inferred:</strong> Packet timestamps and inter-arrival intervals are{' '}
            <strong>Observed</strong> directly from the capture, while periodicity/beaconing classifications are{' '}
            <strong>Inferred</strong> behavioral indicators. <strong>HIGH</strong> indicates persistent low-jitter
            periodic cadence; <strong>ELEVATED</strong> indicates above-baseline timing regularity without a confirmed
            beacon signature. Legitimate VPN keep-alives can also exhibit regular cadence.
          </InfoNote>

          {anomalies.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.75rem' }}>
              {anomalies.map((a, i) => (
                <BeaconingRow key={a.anomaly_id ?? i} anomaly={a} onNavigate={() => navigate(`/analysis/${a.analysis_id}`)} />
              ))}
            </div>
          ) : (
            <p style={{ margin: '0.75rem 0 0', fontSize: 12, color: 'var(--text-muted)' }}>
              No HIGH or ELEVATED behavioral timing anomalies detected across your captures.
            </p>
          )}

          {beaconingSummaries.length > 0 && (
            <div style={{ marginTop: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setShowNormalBeaconing((v) => !v)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  background: 'transparent', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '0.35rem 0.75rem',
                  fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', cursor: 'pointer',
                }}
              >
                <ChevronDown size={12} style={{
                  transform: showNormalBeaconing ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 0.15s',
                }} />
                {showNormalBeaconing ? 'Hide' : 'Show'} all {beaconingSummaries.length} session timing summaries
              </button>
              {showNormalBeaconing && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.625rem' }}>
                  {beaconingSummaries.map((b, i) => (
                    <BeaconingContextRow
                      key={b.analysis_id ?? i}
                      summary={b}
                      onNavigate={b.analysis_id ? () => navigate(`/analysis/${b.analysis_id}`) : undefined}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      )}

      {/* ── 4. ML Explainability ──────────────────────────── */}
      {mlExplanations.length > 0 && (
        <Card>
          <SectionHeader
            icon={Cpu}
            label="ML Explainability"
            subtitle="Random Forest traffic categorization and feature attribution"
            color="var(--blue)"
            bg="var(--blue-light)"
            border="var(--blue-border)"
            right={
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)' }}>
                {mlExplanations.length} session{mlExplanations.length !== 1 ? 's' : ''}
              </span>
            }
          />
          <InfoNote>
            Classifications are produced by a scikit-learn model trained on the VNAT dataset. A predicted application
            category (e.g., CHAT, STREAMING, or C2) reflects statistical similarity to training flows — it is{' '}
            <strong>never proof of malicious activity</strong>. Short captures (&lt;30 packets), missing flow features,
            or low confidence scores reduce reliability and should be treated as indicative only.
          </InfoNote>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.75rem' }}>
            {visibleML.map((ml, i) => (
              <MLExplainRow
                key={ml.analysis_id ?? i}
                ml={ml}
                onNavigate={ml.analysis_id ? () => navigate(`/analysis/${ml.analysis_id}`) : undefined}
              />
            ))}
            {mlExplanations.length > 4 && (
              <button
                type="button"
                onClick={() => setShowAllML((v) => !v)}
                style={{
                  alignSelf: 'flex-start',
                  background: 'transparent', border: '1px solid var(--border)',
                  borderRadius: 6, padding: '0.35rem 0.75rem',
                  fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', cursor: 'pointer',
                }}
              >
                {showAllML ? 'Show fewer' : `Show all ${mlExplanations.length} ML explanations`}
              </button>
            )}
          </div>
        </Card>
      )}

      {/* ── 5. Recommended Remediation ────────────────────── */}
      {remediations.length > 0 && (
        <Card>
          <SectionHeader
            icon={Shield}
            label="Recommended Remediation"
            subtitle="Deduplicated evidence-based remediation steps mapped to affected parameters"
            color="var(--green-text)"
            bg="var(--green-light)"
            border="var(--green-border)"
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.625rem' }}>
            {remediations.map((rem) => (
              <RemediationRow
                key={rem.key}
                item={rem}
                onNavigateAnalysis={(aid) => navigate(`/analysis/${aid}`)}
              />
            ))}
          </div>
        </Card>
      )}

      {/* ── 6. Overall Risk Summary (Compact & Collapsible) ─ */}
      <Card>
        <SectionHeader
          icon={Shield}
          label="Overall Risk Summary"
          subtitle={`${riskSummaries.length} analyses · ${riskCounts.highCrit} High/Critical · ${riskCounts.medium} Medium · ${riskCounts.lowInfo} Low/Informational`}
          right={
            riskSummaries.length > 0 && (
              <button
                type="button"
                onClick={() => setShowRiskDetails((v) => !v)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                  padding: '0.3rem 0.65rem', borderRadius: 6,
                  border: '1px solid var(--border)', backgroundColor: 'var(--bg-surface)',
                  color: 'var(--text-secondary)', fontSize: 11, fontWeight: 600, cursor: 'pointer',
                }}
              >
                <ChevronDown size={12} style={{
                  transform: showRiskDetails ? 'rotate(180deg)' : 'rotate(0deg)',
                  transition: 'transform 0.15s',
                }} />
                {showRiskDetails ? 'Collapse' : `Expand (${riskSummaries.length})`}
              </button>
            )
          }
        />
        <InfoNote>
          A risk score of 0 does <strong>not</strong> mean the VPN is fully secure — it means no high-risk values were
          found among the parameters visible in this capture. Rules that require parameters not present in the PCAP are
          skipped and do not contribute to the score.
        </InfoNote>

        {riskSummaries.length === 0 ? (
          <p style={{ margin: '0.75rem 0 0', fontSize: 13, color: 'var(--text-muted)' }}>No risk summaries available yet.</p>
        ) : showRiskDetails && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '0.75rem' }}>
            {riskSummaries.map((r, i) => (
              <RiskSummaryRow key={r.analysis_id ?? i} summary={r} onNavigate={() => navigate(`/analysis/${r.analysis_id}`)} />
            ))}
          </div>
        )}
      </Card>

      {/* ── 7. Skipped Security Rules / Unavailable Info ──── */}
      {consolidatedSkipped.length > 0 && (
        <Card>
          <SectionHeader
            icon={HelpCircle}
            label="Skipped Rules & Unavailable Parameters"
            subtitle="Parameters not observable in captured packets (neither passed nor failed)"
            color="var(--text-muted)"
            bg="var(--bg-surface)"
            border="var(--border)"
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {consolidatedSkipped.map((s) => (
              <SkippedRuleRow key={s.key} rule={s} />
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────
// Sub-row components
// ─────────────────────────────────────────────────────────────
function PriorityActionRow({ finding: f, onNavigate }) {
  return (
    <div style={{
      padding: '0.75rem 0.875rem',
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-muted)' }}>{f.finding_id}</span>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', flex: 1, minWidth: 180 }}>
          {f.title}
        </span>
        <span className={`badge ${sevColor(f.severity)}`} style={{ fontSize: 10 }}>{f.severity}</span>
        {(f.risk_contribution ?? 0) > 0 && (
          <span style={{
            fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 9999,
            backgroundColor: 'var(--red-light)', color: 'var(--red-text)',
            border: '1px solid var(--red-border)',
          }}>
            +{f.risk_contribution} risk
          </span>
        )}
        <ObsBadge type={f.observation_type} />
      </div>
      {f.recommendation && (
        <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.5 }}>
          <strong>Action:</strong> {f.recommendation}
        </div>
      )}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-muted)' }}>
        <span>Parameter: <strong style={{ color: 'var(--text-secondary)' }}>{f.affected_parameter || '—'}</strong></span>
        {f.filename && <span style={{ fontFamily: 'monospace', fontSize: 10 }}>📁 {f.filename}</span>}
        <button
          type="button"
          onClick={onNavigate}
          style={{
            marginLeft: 'auto',
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '0.25rem 0.6rem', borderRadius: 6,
            border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
            color: 'var(--blue)', fontSize: 11, fontWeight: 600, cursor: 'pointer',
          }}
        >
          View Analysis <ArrowRight size={10} />
        </button>
      </div>
    </div>
  );
}

function ConsolidatedInsightRow({ group, onNavigateAnalysis }) {
  const [expanded, setExpanded] = useState(false);
  const visibleAnalyses = expanded ? group.analyses : group.analyses.slice(0, 3);

  return (
    <div style={{
      padding: '0.75rem 0.875rem',
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)', borderRadius: 8,
      display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', flex: 1, minWidth: 180 }}>
          {group.title}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 9999,
          backgroundColor: 'var(--bg-card)', color: 'var(--text-secondary)',
          border: '1px solid var(--border)',
        }}>
          {group.occurrences} occurrence{group.occurrences !== 1 ? 's' : ''} · {group.analyses.length} capture{group.analyses.length !== 1 ? 's' : ''}
        </span>
        <span className={`badge ${sevColor(group.severity)}`} style={{ fontSize: 10 }}>{group.severity}</span>
        <ObsBadge type={group.observation_type} />
      </div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
        Affected parameter: <strong style={{ color: 'var(--text-secondary)' }}>{group.affected_parameter || '—'}</strong>
      </div>
      {group.description && (
        <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55 }}>{group.description}</p>
      )}
      {group.analyses.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 2 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Affected analyses:</span>
          {visibleAnalyses.map((a) => (
            <button
              key={a.analysis_id}
              type="button"
              onClick={() => onNavigateAnalysis(a.analysis_id)}
              title={`Open analysis (${a.finding_id})`}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '0.2rem 0.5rem', borderRadius: 5,
                border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
                color: 'var(--blue)', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
              }}
            >
              {a.filename} <ArrowRight size={9} />
            </button>
          ))}
          {group.analyses.length > 3 && (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              style={{
                background: 'transparent', border: 'none', padding: '0.2rem 0.4rem',
                fontSize: 10, fontWeight: 600, color: 'var(--blue)', cursor: 'pointer',
              }}
            >
              {expanded ? 'Show less' : `+${group.analyses.length - 3} more`}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function RemediationRow({ item, onNavigateAnalysis }) {
  return (
    <div style={{
      padding: '0.75rem 0.875rem',
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)', borderRadius: 8,
      display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span className={`badge ${sevColor(item.severity)}`} style={{ fontSize: 10 }}>{item.severity}</span>
        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
          {item.affected_parameter}
        </span>
      </div>
      <p style={{ margin: 0, fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.55 }}>
        {item.recommendation}
      </p>
      {item.evidence && (
        <div style={{
          fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)',
          backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '0.35rem 0.6rem',
        }}>
          🔗 {item.evidence}
        </div>
      )}
      {item.analyses.length > 0 && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Applies to:</span>
          {item.analyses.slice(0, 4).map((a) => (
            <button
              key={a.analysis_id}
              type="button"
              onClick={() => onNavigateAnalysis(a.analysis_id)}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '0.2rem 0.5rem', borderRadius: 5,
                border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
                color: 'var(--blue)', fontSize: 10, fontFamily: 'monospace', cursor: 'pointer',
              }}
            >
              {a.filename} <ArrowRight size={9} />
            </button>
          ))}
          {item.analyses.length > 4 && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{item.analyses.length - 4} more</span>
          )}
        </div>
      )}
    </div>
  );
}

function RiskSummaryRow({ summary: r, onNavigate }) {
  const score = r.overall_risk_score ?? r.risk_score ?? r.score ?? 0;
  const level = r.risk_level ?? r.level ?? 'Unknown';
  const explanation = r.score_explanation ?? r.explanation;
  const scoreColor =
    level === 'Critical' || level === 'High' ? 'var(--red)' :
    level === 'Medium' ? 'var(--yellow)' :
    level === 'Informational' || score === 0 ? 'var(--green)' : 'var(--blue)';

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap',
      padding: '0.5rem 0.75rem',
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)', borderRadius: 8,
    }}>
      <div style={{ textAlign: 'center', flexShrink: 0, minWidth: 54 }}>
        <div style={{ fontSize: 16, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>{score}</div>
        <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600 }}>{level}</div>
      </div>
      <div style={{ flex: 1, minWidth: 180 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          {r.filename && (
            <span style={{ fontFamily: 'monospace', fontSize: 11, fontWeight: 600, color: 'var(--text-primary)' }}>
              📁 {r.filename}
            </span>
          )}
          {r.created_at && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{fmtDate(r.created_at)}</span>
          )}
        </div>
        {explanation && (
          <p style={{ margin: '2px 0 0', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.45 }}>
            {explanation}
          </p>
        )}
      </div>
      {r.analysis_id && (
        <button type="button" onClick={onNavigate} style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '0.25rem 0.55rem', borderRadius: 6,
          border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
          color: 'var(--blue)', fontSize: 11, fontWeight: 600, cursor: 'pointer', flexShrink: 0,
        }}>
          View <ArrowRight size={10} />
        </button>
      )}
    </div>
  );
}

function SkippedRuleRow({ rule: s }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 8,
      padding: '0.5rem 0.75rem',
      backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 7,
    }}>
      <XCircle size={13} style={{ color: 'var(--text-muted)', marginTop: 2, flexShrink: 0 }} />
      <div style={{ flex: 1 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
            {s.rule}
          </span>
          {s.count > 1 && (
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>
              ({s.count} sessions)
            </span>
          )}
        </div>
        {s.reason && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{s.reason}</div>
        )}
      </div>
    </div>
  );
}

function BeaconingRow({ anomaly: a, onNavigate }) {
  const isHigh = a.anomaly_level === 'HIGH';
  const levelColor = isHigh ? 'var(--red)' : 'var(--yellow-text)';

  return (
    <div style={{
      padding: '0.75rem 0.875rem',
      backgroundColor: 'var(--bg-surface)',
      border: `1px solid ${isHigh ? 'var(--red-border)' : 'var(--border)'}`,
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', flex: 1 }}>{a.title}</span>
        <span style={{
          fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 9999,
          backgroundColor: isHigh ? 'var(--red-light)' : 'var(--yellow-light)',
          color: levelColor,
          border: `1px solid ${isHigh ? 'var(--red-border)' : 'var(--yellow-border)'}`,
        }}>
          {a.anomaly_level}
        </span>
        <ObsBadge type={a.observation_type || 'Inferred'} />
      </div>
      {a.description && (
        <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55 }}>{a.description}</p>
      )}
      {a.evidence && (
        <div style={{
          fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)',
          backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 6, padding: '0.35rem 0.6rem',
        }}>
          🔗 Observed timing evidence: {a.evidence}
        </div>
      )}
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 11, color: 'var(--text-muted)' }}>
        {a.anomaly_score !== undefined && (
          <span>Anomaly score: <strong style={{ color: 'var(--text-secondary)' }}>{a.anomaly_score}</strong></span>
        )}
        {a.beacon_detected !== undefined && (
          <span>Beacon detected: <strong style={{ color: a.beacon_detected ? 'var(--red)' : 'var(--green)' }}>
            {a.beacon_detected ? 'Yes' : 'No'}
          </strong></span>
        )}
        {a.estimated_interval_sec !== undefined && (
          <span>Est. interval: <strong style={{ color: 'var(--text-secondary)' }}>{a.estimated_interval_sec}s</strong></span>
        )}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, flexWrap: 'wrap' }}>
        {a.filename && (
          <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-muted)' }}>📁 {a.filename}</div>
        )}
        <button type="button" onClick={onNavigate} style={{
          marginLeft: 'auto',
          display: 'flex', alignItems: 'center', gap: 4,
          padding: '0.3rem 0.6rem', borderRadius: 6,
          border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
          color: 'var(--blue)', fontSize: 11, fontWeight: 600, cursor: 'pointer',
        }}>
          View Analysis <ArrowRight size={10} />
        </button>
      </div>
    </div>
  );
}

function BeaconingContextRow({ summary: b, onNavigate }) {
  return (
    <div style={{
      padding: '0.65rem 0.875rem',
      backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 4,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', flex: 1 }}>
          {b.verdict || 'Timing Summary'}
        </span>
        {b.anomaly_level && (
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)' }}>
            {b.anomaly_level} (score {b.anomaly_score ?? '—'})
          </span>
        )}
        {onNavigate && (
          <button type="button" onClick={onNavigate} style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '0.2rem 0.5rem', borderRadius: 5,
            border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
            color: 'var(--blue)', fontSize: 10, fontWeight: 600, cursor: 'pointer',
          }}>
            View <ArrowRight size={9} />
          </button>
        )}
      </div>
      {b.filename && (
        <div style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-muted)' }}>📁 {b.filename}</div>
      )}
      {b.explanation && (
        <p style={{ margin: 0, fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{b.explanation}</p>
      )}
    </div>
  );
}

function MLExplainRow({ ml, onNavigate }) {
  const rawConf = ml.confidence_score ?? ml.confidence;
  const conf = typeof rawConf === 'number' ? (rawConf > 1 ? rawConf / 100 : rawConf) : null;
  const isLow = conf !== null && conf < 0.5;
  const missing = ml.features_required_missing ?? [];

  return (
    <div style={{
      padding: '0.75rem 0.875rem',
      backgroundColor: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 8, display: 'flex', flexDirection: 'column', gap: 6,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--blue)' }}>
          {ml.predicted_category ?? 'Unknown'}
        </span>
        <span style={{
          fontSize: 10, fontWeight: 600, padding: '2px 7px', borderRadius: 9999,
          backgroundColor: isLow ? 'var(--yellow-light)' : 'var(--blue-light)',
          color: isLow ? 'var(--yellow-text)' : 'var(--blue)',
          border: `1px solid ${isLow ? 'var(--yellow-border)' : 'var(--blue-border)'}`,
        }}>
          {conf !== null ? `${(conf * 100).toFixed(1)}% confidence` : ml.confidence_level ?? '—'}
        </span>
        {ml.model_status && (
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>({ml.model_status})</span>
        )}
        {ml.filename && (
          <span style={{ fontFamily: 'monospace', fontSize: 10, color: 'var(--text-muted)', marginLeft: 'auto' }}>
            📁 {ml.filename}
          </span>
        )}
      </div>
      {ml.summary && (
        <p style={{ margin: 0, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.55 }}>{ml.summary}</p>
      )}
      {ml.model_note && (
        <p style={{ margin: 0, fontSize: 11, color: 'var(--yellow-text)', lineHeight: 1.5 }}>
          ⚠️ Limitation: {ml.model_note}
        </p>
      )}
      {missing.length > 0 && (
        <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          Missing features: <span style={{ fontFamily: 'monospace' }}>{missing.join(', ')}</span>
        </div>
      )}
      {(ml.top_contributing_factors ?? []).length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 3 }}>Top contributing factors:</div>
          <ul style={{ margin: 0, paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: 2 }}>
            {(ml.top_contributing_factors ?? []).map((fc, i) => (
              <li key={i} style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                {typeof fc === 'object' && fc !== null ? (
                  <>
                    <strong>{fc.feature_name ?? fc.feature_key ?? 'Feature'}</strong>
                    {fc.observed_value !== undefined && ` (${fc.observed_value})`}
                    {fc.impact_percentage !== undefined && ` — ${fc.impact_percentage}% impact`}
                    {fc.reason && `: ${fc.reason}`}
                  </>
                ) : (
                  fc
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {onNavigate && (
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button type="button" onClick={onNavigate} style={{
            display: 'inline-flex', alignItems: 'center', gap: 4,
            padding: '0.25rem 0.55rem', borderRadius: 6,
            border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
            color: 'var(--blue)', fontSize: 11, fontWeight: 600, cursor: 'pointer',
          }}>
            View Analysis <ArrowRight size={10} />
          </button>
        </div>
      )}
    </div>
  );
}

function EmptyAdvisor({ onAnalyze }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', maxWidth: 960, margin: '0 auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 9,
          backgroundColor: 'var(--blue-light)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: '1px solid var(--blue-border)', flexShrink: 0,
        }}>
          <Sparkles size={18} style={{ color: 'var(--blue)' }} />
        </div>
        <h1 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>
          AI Security Advisor
        </h1>
      </div>
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
        padding: '3rem 1.5rem', textAlign: 'center', gap: 12,
        backgroundColor: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
      }}>
        <Sparkles size={32} style={{ color: 'var(--text-muted)', opacity: 0.6 }} />
        <p style={{ margin: 0, fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>
          No analyses yet
        </p>
        <p style={{ margin: 0, fontSize: 12, color: 'var(--text-muted)', maxWidth: 360 }}>
          Upload a PCAP file to generate security findings, risk summaries and behavioral insights
          that the advisor will explain here.
        </p>
        <button type="button" onClick={onAnalyze} style={{
          marginTop: 8, padding: '0.5rem 1.25rem', borderRadius: 7,
          border: '1px solid var(--blue-border)', backgroundColor: 'var(--blue-light)',
          color: 'var(--blue)', fontSize: 13, fontWeight: 600, cursor: 'pointer',
        }}>
          Analyze PCAP
        </button>
      </div>
    </div>
  );
}
