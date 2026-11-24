import { ShieldAlert, AlertTriangle, Radio, Lock, CheckCircle2, RotateCcw } from 'lucide-react';

export default function ThreatMatrix({ threatCounts = {}, activeFilter = null, onSelectFilter }) {
  const items = [
    {
      key: 'weak_dh',
      title: 'Weak DH Groups',
      count: threatCounts.weak_dh ?? 0,
      description: 'Diffie-Hellman groups < 14 (MODP 1024 / Group 2/5)',
      rule: 'SEC-01',
      severity: 'High',
      color: 'var(--red)',
      bg: 'var(--red-light)',
      border: 'var(--red-border)',
      Icon: ShieldAlert,
    },
    {
      key: 'ikev1_aggressive',
      title: 'IKEv1 Aggressive Mode',
      count: threatCounts.ikev1_aggressive ?? 0,
      description: 'Legacy exchange vulnerable to offline PSK cracking',
      rule: 'SEC-02',
      severity: 'Medium',
      color: 'var(--amber)',
      bg: 'var(--amber-light)',
      border: 'var(--amber-border)',
      Icon: AlertTriangle,
    },
    {
      key: 'beaconing',
      title: 'Periodic Beaconing',
      count: threatCounts.beaconing ?? 0,
      description: 'Automated inter-arrival timing & low jitter regularity',
      rule: 'SEC-06',
      severity: 'Behavioral',
      color: '#8B5CF6',
      bg: 'rgba(139, 92, 246, 0.08)',
      border: 'rgba(139, 92, 246, 0.25)',
      Icon: Radio,
    },
    {
      key: 'strong_encryption',
      title: 'Strong AEAD Ciphers',
      count: threatCounts.strong_encryption ?? 0,
      description: 'Modern authenticated ciphers observed (AES-GCM / CCM)',
      rule: 'SEC-03',
      severity: 'Compliant',
      color: 'var(--green)',
      bg: 'var(--green-light)',
      border: 'var(--green-border)',
      Icon: Lock,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
            Threat Breakdown Matrix
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>
            Database-derived cryptographic & behavioral indicators
          </span>
        </div>

        {activeFilter && (
          <button
            type="button"
            onClick={() => onSelectFilter(null)}
            style={{
              display: 'inline-flex', alignItems: 'center', gap: 5,
              fontSize: 11, fontWeight: 600, color: 'var(--blue)',
              background: 'none', border: 'none', cursor: 'pointer', padding: '2px 6px',
            }}
          >
            <RotateCcw size={12} />
            Reset Filter
          </button>
        )}
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
        gap: '0.875rem',
      }}>
        {items.map((item) => {
          const isSelected = activeFilter === item.key;
          const { Icon } = item;

          return (
            <button
              key={item.key}
              type="button"
              onClick={() => onSelectFilter(isSelected ? null : item.key)}
              style={{
                backgroundColor: isSelected ? item.bg : 'var(--bg-card)',
                borderRadius: 12,
                border: `1.5px solid ${isSelected ? item.color : 'var(--border)'}`,
                padding: '1rem',
                textAlign: 'left',
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
                boxShadow: isSelected ? 'var(--shadow-md)' : 'var(--shadow-sm)',
                transition: 'all 0.15s ease',
                position: 'relative',
              }}
              onMouseOver={(e) => {
                if (!isSelected) e.currentTarget.style.borderColor = item.color;
              }}
              onMouseOut={(e) => {
                if (!isSelected) e.currentTarget.style.borderColor = 'var(--border)';
              }}
            >
              {/* Header row: Icon + Rule tag */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 8,
                  backgroundColor: item.bg,
                  border: `1px solid ${item.border}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: item.color,
                }}>
                  <Icon size={16} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '2px 6px', borderRadius: 4,
                    backgroundColor: 'var(--bg-surface)', color: 'var(--text-muted)', border: '1px solid var(--border)',
                  }}>
                    {item.rule}
                  </span>
                  {isSelected && (
                    <span style={{ color: item.color, display: 'flex', alignItems: 'center' }}>
                      <CheckCircle2 size={14} />
                    </span>
                  )}
                </div>
              </div>

              {/* Number and Title */}
              <div>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                  <span style={{ fontSize: 22, fontWeight: 800, color: 'var(--text-primary)', lineHeight: 1.1 }}>
                    {item.count}
                  </span>
                  <span style={{ fontSize: 11, fontWeight: 600, color: item.color }}>
                    {item.severity}
                  </span>
                </div>
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}>
                  {item.title}
                </div>
              </div>

              {/* Description */}
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.35 }}>
                {item.description}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

