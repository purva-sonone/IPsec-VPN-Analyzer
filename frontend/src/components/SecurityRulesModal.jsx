import { useState } from 'react';
import { Shield, X, CheckCircle2, AlertTriangle, XCircle, Info, Lock, Key, Activity } from 'lucide-react';

const RULES = [
  {
    id: 'SEC-01',
    category: 'Key Exchange',
    title: 'Adequate Diffie-Hellman Group',
    severity: 'High',
    description: 'Requires Diffie-Hellman group >= 14 (2048-bit MODP) or modern elliptic curves (Group 19/20/21). Groups 1, 2, and 5 (768/1024-bit) are vulnerable to state-sponsored precomputation attacks.',
    recommendation: 'Upgrade DH group to at least Group 14 or Group 19 (ECP-256).'
  },
  {
    id: 'SEC-02',
    category: 'Protocol Version',
    title: 'IKE Protocol Version Audit',
    severity: 'Medium',
    description: 'Audits whether modern IKEv2 (RFC 7296) is deployed. Legacy IKEv1 suffers from amplification risks, lack of native NAT-T, and complex multi-round exchanges.',
    recommendation: 'Migrate legacy IKEv1 tunnels to IKEv2 for enhanced security and faster re-keying.'
  },
  {
    id: 'SEC-03',
    category: 'Encryption',
    title: 'Strong Encryption Cipher',
    severity: 'Critical',
    description: 'Ensures confidentiality using modern authenticated ciphers (AES-GCM-256/128, ChaCha20-Poly1305) or AES-CBC. Flags deprecated 3DES, DES, or NULL ciphers.',
    recommendation: 'Enforce AES-GCM-256 for combined confidentiality and hardware-accelerated integrity.'
  },
  {
    id: 'SEC-04',
    category: 'Authentication',
    title: 'Authentication Method Robustness',
    severity: 'Medium',
    description: 'Evaluates authentication mechanisms. Digital certificates (RSA-Sig, ECDSA) provide strong non-repudiation compared to weak pre-shared keys (PSK).',
    recommendation: 'Deploy PKI certificate-based mutual authentication with ECDSA signatures.'
  },
  {
    id: 'SEC-05',
    category: 'Payload Security',
    title: 'ESP Payload Protection',
    severity: 'High',
    description: 'Verifies that user data packets are protected by Encapsulating Security Payload (ESP). Unencrypted or plaintext control flows without ESP leave traffic exposed.',
    recommendation: 'Ensure ESP tunnel mode is enforced on all data interfaces.'
  },
  {
    id: 'SEC-06',
    category: 'Behavioral Timing',
    title: 'C2 Beaconing Cadence Detection',
    severity: 'High',
    description: 'Analyzes packet inter-arrival times (IAT), arrival jitter, and interval regularity to identify automated implant beaconing or scheduled callbacks.',
    recommendation: 'Investigate regular callback intervals and cross-reference with endpoint process telemetry.'
  },
  {
    id: 'SEC-07',
    category: 'Traffic Classification',
    title: 'Encrypted Traffic Category Model',
    severity: 'Informational',
    description: 'Uses Random Forest (500 decision trees) trained on VNAT benchmark dataset to identify hidden traffic profiles (C2, VOIP, Streaming, Chat, File Transfer) based solely on timing and packet cadence.',
    recommendation: 'Use ML traffic classification alongside firewall DPI to spot unusual high-throughput or covert tunnels.'
  }
];

export default function SecurityRulesModal({ isOpen, onClose }) {
  const [filter, setFilter] = useState('All');

  if (!isOpen) return null;

  const filteredRules = filter === 'All'
    ? RULES
    : RULES.filter(r => r.category === filter || r.severity === filter);

  const categories = ['All', 'Key Exchange', 'Protocol Version', 'Encryption', 'Payload Security', 'Behavioral Timing', 'Traffic Classification'];

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 100,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      backgroundColor: 'rgba(15, 23, 42, 0.65)',
      backdropFilter: 'blur(4px)',
      padding: '1rem',
    }}>
      <div
        className="card"
        style={{
          width: '100%',
          maxWidth: '800px',
          maxHeight: '90vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          backgroundColor: 'var(--bg-card)',
          borderColor: 'var(--border)',
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
        }}
      >
        {/* Header */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '1.25rem 1.5rem',
          borderBottom: '1px solid var(--border)',
          backgroundColor: 'var(--bg-surface)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: 36,
              height: 36,
              borderRadius: 8,
              backgroundColor: 'var(--blue-light)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}>
              <Shield size={20} style={{ color: 'var(--blue)' }} />
            </div>
            <div>
              <h2 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Security Rules & Detection Catalog
              </h2>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', margin: '2px 0 0' }}>
                Standard evaluation heuristics for IPsec compliance & threat modeling
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              color: 'var(--text-muted)',
              padding: '0.375rem',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
            }}
            title="Close"
          >
            <X size={18} />
          </button>
        </div>

        {/* Filters */}
        <div style={{
          display: 'flex',
          gap: '0.5rem',
          padding: '0.75rem 1.5rem',
          borderBottom: '1px solid var(--border-muted)',
          overflowX: 'auto',
          backgroundColor: 'var(--bg-card)',
        }}>
          {categories.map(cat => (
            <button
              key={cat}
              onClick={() => setFilter(cat)}
              style={{
                padding: '0.25rem 0.65rem',
                borderRadius: '9999px',
                fontSize: '0.75rem',
                fontWeight: 600,
                border: '1px solid',
                cursor: 'pointer',
                whiteSpace: 'nowrap',
                transition: 'all 0.15s ease',
                backgroundColor: filter === cat ? 'var(--blue)' : 'transparent',
                borderColor: filter === cat ? 'var(--blue)' : 'var(--border)',
                color: filter === cat ? '#FFFFFF' : 'var(--text-secondary)',
              }}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Content list */}
        <div style={{
          padding: '1.25rem 1.5rem',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '0.875rem',
          backgroundColor: 'var(--bg-page)',
        }}>
          {filteredRules.map(rule => (
            <div
              key={rule.id}
              style={{
                padding: '1rem',
                borderRadius: '10px',
                border: '1px solid var(--border)',
                backgroundColor: 'var(--bg-card)',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.5rem',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{
                    fontSize: '0.7rem',
                    fontFamily: 'monospace',
                    fontWeight: 700,
                    padding: '2px 6px',
                    borderRadius: 4,
                    backgroundColor: 'var(--bg-muted)',
                    color: 'var(--text-secondary)',
                  }}>
                    {rule.id}
                  </span>
                  <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {rule.title}
                  </span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{rule.category}</span>
                  <span className={`badge badge-${rule.severity.toLowerCase()}`}>
                    {rule.severity}
                  </span>
                </div>
              </div>

              <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                {rule.description}
              </p>

              <div style={{
                display: 'flex',
                alignItems: 'baseline',
                gap: '0.5rem',
                fontSize: '0.75rem',
                color: 'var(--blue-text)',
                backgroundColor: 'var(--blue-light)',
                padding: '0.4rem 0.65rem',
                borderRadius: 6,
                marginTop: 2,
              }}>
                <strong style={{ flexShrink: 0 }}>Recommendation:</strong>
                <span>{rule.recommendation}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '0.875rem 1.5rem',
          borderTop: '1px solid var(--border)',
          backgroundColor: 'var(--bg-surface)',
        }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Showing {filteredRules.length} rules
          </span>
          <button
            onClick={onClose}
            className="btn-primary"
            style={{ fontSize: '0.8125rem', padding: '0.35rem 0.85rem' }}
          >
            Close Catalog
          </button>
        </div>
      </div>
    </div>
  );
}

