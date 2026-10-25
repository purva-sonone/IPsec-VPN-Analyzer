// src/lib/utils.js — shared formatters & classifiers

export function fmtDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso + (iso.endsWith('Z') ? '' : 'Z'))
      .toLocaleString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
  } catch { return iso; }
}

/**
 * Returns CSS class names for risk level (light-mode semantic tokens).
 */
export function riskColor(level) {
  switch (level) {
    case 'Critical':
    case 'High':          return { text: 'text-red-700',    bg: 'bg-red-50',    border: 'border-red-200',    badge: 'badge-high' };
    case 'Medium':        return { text: 'text-amber-700',  bg: 'bg-amber-50',  border: 'border-amber-200',  badge: 'badge-medium' };
    case 'Low':           return { text: 'text-blue-700',   bg: 'bg-blue-50',   border: 'border-blue-200',   badge: 'badge-low' };
    default:              return { text: 'text-green-700',  bg: 'bg-green-50',  border: 'border-green-200',  badge: 'badge-info' };
  }
}

/**
 * Returns Tailwind classes for a finding severity badge.
 */
export function sevColor(sev) {
  switch (sev) {
    case 'Critical':
    case 'High':          return 'badge-high';
    case 'Medium':        return 'badge-medium';
    case 'Low':           return 'badge-low';
    default:              return 'badge-info';
  }
}

/**
 * Returns strength info for a cryptographic value string.
 */
export function strengthOf(value) {
  if (!value || value === 'Not Extracted' || value === 'Unknown') return null;
  const STRONG = ['AES-GCM', 'AES-CCM', 'ChaCha20', 'Group 14', 'Group 19', 'Group 20', 'Group 21', 'Group 31', 'ECDSA', 'SHA-256', 'SHA-384', 'SHA-512', 'IKEv2'];
  const WEAK   = ['DES', '3DES', 'RC4', 'RC5', 'NULL', 'Blowfish', 'Group 1', 'Group 2', 'Group 5', 'IKEv1', 'IDEA', 'CAST', 'MD5', 'Alternate 1024-bit MODP', '1024-bit MODP'];

  if (STRONG.some(s => new RegExp(`\\b${s.replace('-', '\\-')}\\b`, 'i').test(value) || value.includes(s)))
    return { label: 'Strong', cls: 'badge strength-strong' };

  if (WEAK.some(w => {
    if (w.startsWith('Group ')) return new RegExp(`\\b${w}\\b`).test(value);
    return value.includes(w);
  })) return { label: 'Weak', cls: 'badge strength-weak' };

  return { label: 'Observed', cls: 'badge strength-observed' };
}

export function mlStatusColor(status) {
  if (status === 'trained_model')    return 'text-purple-700';
  if (status === 'not_applicable')   return 'text-slate-500';
  return 'text-amber-700';
}

/** Returns the badge class for IKE version */
export function ikeBadgeClass(ver) {
  if (ver === 'IKEv2') return 'badge badge-ikev2';
  if (ver === 'IKEv1') return 'badge badge-ikev1';
  return 'badge badge-neutral';
}

/** Returns the badge class for ML category */
export function mlBadgeClass() {
  return 'badge badge-ml';
}
