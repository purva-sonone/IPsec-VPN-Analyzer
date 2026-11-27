// src/lib/api.js — centralised API helpers
// In production (Render), VITE_API_URL is set to the backend service URL.
// In local dev, it falls back to http://localhost:8000.

const rawBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
const BASE = rawBase.endsWith('/api') ? rawBase : `${rawBase}/api`;

/** Return the stored bearer token, or null if not logged in. */
export function getToken() {
  return localStorage.getItem('ipsec_token');
}

/** Return the stored username, or null. */
export function getUser() {
  return localStorage.getItem('ipsec_user');
}

/** Clear the stored session (logout). */
export function clearSession() {
  localStorage.removeItem('ipsec_token');
  localStorage.removeItem('ipsec_user');
}

async function request(url, options = {}) {
  const token = getToken();
  const headers = {
    ...(options.headers || {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };

  const res = await fetch(url, { ...options, headers });

  // Session expired or token invalid — force logout
  if (res.status === 401) {
    clearSession();
    window.location.href = '/';
    throw new Error('Session expired. Please log in again.');
  }

  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      msg = data.detail || data.message || msg;
    } catch {
      // not JSON
    }
    throw new Error(msg);
  }
  return res.json();
}

export const api = {
  baseUrl:    BASE,
  health:     ()     => request(`${BASE}/health`),
  systemDeps: ()     => request(`${BASE}/system/dependencies`),
  upload:     (form) => request(`${BASE}/upload`, { method: 'POST', body: form }),
  history:    ()     => request(`${BASE}/history`),
  stats:      ()     => request(`${BASE}/history/stats`),
  findings:   ()     => request(`${BASE}/findings`),
  advisorStatus: ()  => request(`${BASE}/advisor/status`),
  advisorHistory: (analysisId) => {
    const q = analysisId ? `?analysis_id=${encodeURIComponent(analysisId)}` : '';
    return request(`${BASE}/advisor/history${q}`);
  },
  advisorChat: (message, analysisId, attachmentContext = null) => request(`${BASE}/advisor/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message, analysis_id: analysisId || null, attachment_context: attachmentContext || null }),
  }),
  advisorClear: (analysisId) => {
    const q = analysisId ? `?analysis_id=${encodeURIComponent(analysisId)}` : '';
    return request(`${BASE}/advisor/clear${q}`, { method: 'DELETE' });
  },
  advisorUpload: (formData) => request(`${BASE}/advisor/upload`, { method: 'POST', body: formData }),
  advisorUploadPdf: (formData) => request(`${BASE}/advisor/upload_pdf`, { method: 'POST', body: formData }),
  getById:    (id)   => request(`${BASE}/history/${id}`),
  deleteById: (id)   => request(`${BASE}/history/${id}`, { method: 'DELETE' }),
  demoAnalyze: ()    => request(`${BASE}/sample/demo-analyze`, { method: 'POST' }),
  reportUrl:  (id)   => {
    const token = getToken();
    return token ? `${BASE}/history/${id}/report?token=${encodeURIComponent(token)}` : `${BASE}/history/${id}/report`;
  },
};
