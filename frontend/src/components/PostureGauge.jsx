import { useState } from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, HelpCircle, X } from 'lucide-react';

export default function PostureGauge({ score = 100, totalAnalyses = 0, highRiskCount = 0 }) {
  const [showInfo, setShowInfo] = useState(false);

  // Score clamping & color mapping (80-100: Green, 50-79: Amber, <50: Red)
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));
  
  let statusColor = 'var(--green)';
  let statusBg = 'var(--green-light)';
  let statusBorder = 'var(--green-border)';
  let statusLabel = 'Strong Posture';
  let StatusIcon = ShieldCheck;

  if (clampedScore < 50) {
    statusColor = 'var(--red)';
    statusBg = 'var(--red-light)';
    statusBorder = 'var(--red-border)';
    statusLabel = 'Elevated Risk';
    StatusIcon = ShieldAlert;
  } else if (clampedScore < 80) {
    statusColor = 'var(--amber)';
    statusBg = 'var(--amber-light)';
    statusBorder = 'var(--amber-border)';
    statusLabel = 'Moderate Posture';
    StatusIcon = AlertTriangle;
  }

  // SVG Circular progress math
  const radius = 48;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      borderRadius: 14,
      border: '1px solid var(--border)',
      padding: '1.25rem 1.5rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '1.5rem',
      boxShadow: 'var(--shadow-sm)',
      position: 'relative',
    }}>
      {/* Left side info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Security Posture Index
          </span>
          <button
            type="button"
            onClick={() => setShowInfo(true)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer', padding: 0,
              color: 'var(--text-muted)', display: 'flex', alignItems: 'center',
            }}
            title="Learn how this score is calculated"
          >
            <HelpCircle size={15} />
          </button>
        </div>

        <p style={{ fontSize: 12, color: 'var(--text-secondary)', margin: '0 0 10px', lineHeight: 1.45 }}>
          Aggregate network cryptographic health evaluated across {totalAnalyses} PCAP capture{totalAnalyses !== 1 ? 's' : ''}.
        </p>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            padding: '3px 9px', borderRadius: 9999,
            fontSize: 11, fontWeight: 600,
            backgroundColor: statusBg, color: statusColor, border: `1px solid ${statusBorder}`,
          }}>
            <StatusIcon size={13} />
            {statusLabel}
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {highRiskCount > 0 ? `${highRiskCount} high-risk finding${highRiskCount !== 1 ? 's' : ''} detected` : 'No high-risk parameters active'}
          </span>
        </div>
      </div>

      {/* Right side Radial Gauge */}
      <div style={{ position: 'relative', width: 114, height: 114, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <svg width="114" height="114" viewBox="0 0 120 120" style={{ transform: 'rotate(-90deg)' }}>
          {/* Background circle */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke="var(--border)"
            strokeWidth="9"
          />
          {/* Animated score circle */}
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke={statusColor}
            strokeWidth="9"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.8s ease' }}
          />
        </svg>

        {/* Center score label */}
        <div style={{
          position: 'absolute',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
        }}>
          <span style={{ fontSize: 24, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1 }}>
            {clampedScore}
          </span>
          <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            / 100
          </span>
        </div>
      </div>

      {/* Info Modal / Explanation */}
      {showInfo && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 100,
          backgroundColor: 'rgba(0,0,0,0.45)', backdropFilter: 'blur(3px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1rem',
        }}>
          <div style={{
            backgroundColor: 'var(--bg-card)', borderRadius: 14,
            border: '1px solid var(--border)', maxWidth: 520, width: '100%',
            padding: '1.5rem', boxShadow: 'var(--shadow-lg)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <ShieldCheck size={20} color="var(--blue)" />
                <h3 style={{ fontSize: 16, fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
                  Security Posture Index Calculation
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowInfo(false)}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <p style={{ margin: 0 }}>
                The <b>Security Posture Index</b> is an automated composite score evaluating observable cryptographic security margins across all processed PCAPs in your database.
              </p>
              
              <div style={{ backgroundColor: 'var(--bg-surface)', padding: '0.75rem 1rem', borderRadius: 8, border: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>How It Is Calculated:</div>
                <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12 }}>
                  <li><b>100 Points Base:</b> High-risk findings (e.g. 3DES, weak DH groups &lt; 14) deduct 20–30 points.</li>
                  <li><b>Medium Risk Deductions:</b> Legacy protocol parameters (e.g. IKEv1, unauthenticated flows) deduct 10–15 points.</li>
                  <li><b>Evidence Coverage Awareness:</b> Unobservable or skipped parameters (e.g. encrypted payloads without IKE handshakes) are explicitly not penalized.</li>
                </ul>
              </div>

              <div style={{ backgroundColor: 'var(--blue-light)', padding: '0.625rem 0.875rem', borderRadius: 8, border: '1px solid var(--blue-border)', color: 'var(--text-primary)', fontSize: 12 }}>
                <b>Notice & Limitations:</b> This metric is a project-defined heuristic synthesis. It does <b>not</b> constitute an official NIST SP 800-77 Rev. 1 compliance certification or legal security audit.
              </div>
            </div>

            <div style={{ marginTop: '1.25rem', textAlign: 'right' }}>
              <button
                type="button"
                onClick={() => setShowInfo(false)}
                className="btn-primary"
                style={{ padding: '0.45rem 1rem', fontSize: 13, borderRadius: 6 }}
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

