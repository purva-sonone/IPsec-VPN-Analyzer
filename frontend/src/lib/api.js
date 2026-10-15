// src/lib/api.js — centralised API helpers
// In production (Render), VITE_API_URL is set to the backend service URL.
// In local dev, it falls back to localhost:8000.
const BASE = `${import.meta.env.VITE_API_URL || 'http://localhost:8000'}/api`;

export const api = {
  health:      ()    => fetch(`${BASE}/health`).then(r => r.json()),
  systemDeps:  ()    => fetch(`${BASE}/system/dependencies`).then(r => r.json()),
  upload:  (form)    => fetch(`${BASE}/upload`, { method:'POST', body: form }).then(async r => {
    const data = await r.json();
    if (!r.ok) throw new Error(data.detail || r.statusText);
    return data;
  }),
  history:  ()   => fetch(`${BASE}/history`).then(r => r.json()),
  stats:    ()   => fetch(`${BASE}/history/stats`).then(r => r.json()),
  getById:  (id) => fetch(`${BASE}/history/${id}`).then(async r => {
    if (!r.ok) throw new Error('Not found');
    return r.json();
  }),
  deleteById: (id) => fetch(`${BASE}/history/${id}`, { method:'DELETE' }).then(r => r.json()),
  reportUrl:  (id) => `${BASE}/history/${id}/report`,
};
