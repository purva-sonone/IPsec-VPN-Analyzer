// src/lib/api.js — centralised API helpers
// In production (Render), VITE_API_URL is set to the backend service URL.
// In local dev, it falls back to http://localhost:8000.

const rawBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
const BASE = rawBase.endsWith('/api') ? rawBase : `${rawBase}/api`;

async function request(url, options = {}) {
  const res = await fetch(url, options);
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
  getById:    (id)   => request(`${BASE}/history/${id}`),
  deleteById: (id)   => request(`${BASE}/history/${id}`, { method: 'DELETE' }),
  reportUrl:  (id)   => `${BASE}/history/${id}/report`,
};
