import { Laptop, Server, Network, ShieldCheck, ArrowRight, CheckCircle2, AlertCircle, HelpCircle } from 'lucide-react';

export default function TunnelTopologyCard({ capture = null }) {
  // Extract parameters from capture
  const ikeVer = capture?.ike_version || 'Not Observed';
  const dhGroup = capture?.dh_group || 'Not Extracted';
  const enc = capture?.encryption || 'Not Extracted';
  const vpnMode = capture?.vpn_mode || 'Tunnel (Inferred)';
  const protocols = capture?.protocols || '';
  const hasIke = protocols.includes('IKE') || ikeVer.includes('IKE');
  const hasEsp = protocols.includes('ESP') || protocols.includes('AH');

  const isDhWeak = dhGroup.toLowerCase().includes('1024') || dhGroup.toLowerCase().includes('group 2') || dhGroup.toLowerCase().includes('group 5');
  const isEncStrong = enc.toLowerCase().includes('gcm') || enc.toLowerCase().includes('ccm') || enc.toLowerCase().includes('chacha');

  return (
    <div style={{
      backgroundColor: 'var(--bg-card)',
      borderRadius: 14,
      border: '1px solid var(--border)',
      padding: '1.25rem 1.5rem',
      boxShadow: 'var(--shadow-sm)',
      display: 'flex',
      flexDirection: 'column',
      gap: '1rem',
    }}>
      {/* Title */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
        <div>
          <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>
            VPN Tunnel Topology & Cryptographic Flow
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 8 }}>
            Architecture diagram reflecting active / latest capture parameters
          </span>
        </div>

        {capture?.filename && (
          <span style={{
            fontSize: 11, fontWeight: 500, color: 'var(--text-secondary)',
            backgroundColor: 'var(--bg-surface)', padding: '3px 8px', borderRadius: 6,
            border: '1px solid var(--border)', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            Capture: {capture.filename}
          </span>
        )}
      </div>

      {/* Topology Diagram Flow */}
      <div style={{
        backgroundColor: 'var(--bg-surface)',
        borderRadius: 12,
        border: '1px solid var(--border)',
        padding: '1.25rem 1rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '0.5rem',
        overflowX: 'auto',
      }}>
        {/* Node 1: Client Endpoint */}
        <div style={{
          minWidth: 130, flex: 1, backgroundColor: 'var(--bg-card)',
          borderRadius: 10, border: '1px solid var(--border)', padding: '0.875rem 0.75rem',
          textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{
            width: 34, height: 34, borderRadius: '50%',
            backgroundColor: 'var(--blue-light)', color: 'var(--blue)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Laptop size={17} />
          </div>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
            Client Endpoint
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
            Initiator Host
          </div>
        </div>

        {/* Connector 1: Control Plane (IKE Exchange) */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, minWidth: 140, flex: 1.2 }}>
          <div style={{
            fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
            color: hasIke ? 'var(--blue)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 4,
          }}>
            {hasIke ? <CheckCircle2 size={11} color="var(--blue)" /> : <HelpCircle size={11} />}
            Control Plane
          </div>

          <div style={{
            width: '100%', height: 2,
            backgroundColor: hasIke ? 'var(--blue)' : 'var(--border)',
            position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ArrowRight size={14} color={hasIke ? 'var(--blue)' : 'var(--text-muted)'} style={{ position: 'absolute', right: -6 }} />
          </div>

          <div style={{
            backgroundColor: 'var(--bg-card)', padding: '3px 7px', borderRadius: 6,
            border: '1px solid var(--border)', fontSize: 10, textAlign: 'center',
          }}>
            <span style={{ fontWeight: 600, color: hasIke ? 'var(--text-primary)' : 'var(--text-muted)' }}>
              {ikeVer !== 'Not Observed' ? ikeVer : 'IKE Not Observed'}
            </span>
            <div style={{ fontSize: 9, color: isDhWeak ? 'var(--red)' : 'var(--text-muted)' }}>
              DH: {dhGroup}
            </div>
          </div>
        </div>

        {/* Node 2: Security Gateway */}
        <div style={{
          minWidth: 130, flex: 1, backgroundColor: 'var(--bg-card)',
          borderRadius: 10, border: '1px solid var(--border)', padding: '0.875rem 0.75rem',
          textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{
            width: 34, height: 34, borderRadius: '50%',
            backgroundColor: 'rgba(16, 185, 129, 0.12)', color: 'var(--green)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Server size={17} />
          </div>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
            Security Gateway
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
            IPsec Responder
          </div>
        </div>

        {/* Connector 2: Data Plane (ESP Tunnel) */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, minWidth: 140, flex: 1.2 }}>
          <div style={{
            fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em',
            color: hasEsp ? 'var(--green)' : 'var(--text-muted)',
            display: 'flex', alignItems: 'center', gap: 4,
          }}>
            {hasEsp ? <ShieldCheck size={11} color="var(--green)" /> : <AlertCircle size={11} />}
            Data Plane (ESP)
          </div>

          <div style={{
            width: '100%', height: 2,
            backgroundColor: hasEsp ? 'var(--green)' : 'var(--border)',
            position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <ArrowRight size={14} color={hasEsp ? 'var(--green)' : 'var(--text-muted)'} style={{ position: 'absolute', right: -6 }} />
          </div>

          <div style={{
            backgroundColor: 'var(--bg-card)', padding: '3px 7px', borderRadius: 6,
            border: '1px solid var(--border)', fontSize: 10, textAlign: 'center',
          }}>
            <span style={{ fontWeight: 600, color: hasEsp ? 'var(--text-primary)' : 'var(--text-muted)' }}>
              {vpnMode}
            </span>
            <div style={{ fontSize: 9, color: isEncStrong ? 'var(--green)' : 'var(--text-muted)' }}>
              Cipher: {enc !== 'Not Extracted' ? enc : 'Payload Encrypted'}
            </div>
          </div>
        </div>

        {/* Node 3: Internal Protected Network */}
        <div style={{
          minWidth: 130, flex: 1, backgroundColor: 'var(--bg-card)',
          borderRadius: 10, border: '1px solid var(--border)', padding: '0.875rem 0.75rem',
          textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
          boxShadow: 'var(--shadow-sm)',
        }}>
          <div style={{
            width: 34, height: 34, borderRadius: '50%',
            backgroundColor: 'rgba(99, 102, 241, 0.12)', color: '#6366F1',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            <Network size={17} />
          </div>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
            Protected Network
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
            Encapsulated Subnet
          </div>
        </div>
      </div>

      {/* Legend & Evidence Disclosure */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        fontSize: 11, color: 'var(--text-secondary)', flexWrap: 'wrap', gap: 8,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: 'var(--blue)', display: 'inline-block' }} />
            Observed Control Flow
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: 'var(--green)', display: 'inline-block' }} />
            Observed ESP Flow
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: 'var(--text-muted)', display: 'inline-block' }} />
            Inferred / Encrypted
          </span>
        </div>

        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontStyle: 'italic' }}>
          *Payload inner headers remain encrypted without session secrets.
        </span>
      </div>
    </div>
  );
}

