import { useState } from 'react';
import { Shield, User, Lock, Eye, EyeOff, Loader2, AlertCircle } from 'lucide-react';
import ThemeToggle from '../components/ThemeToggle';

// ── Auth API helpers ──────────────────────────────────────────────────────────
const rawBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
const AUTH_BASE = rawBase.endsWith('/api') ? rawBase : `${rawBase}/api`;

async function authRequest(path, body) {
  const res = await fetch(`${AUTH_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

// ── InputField ─────────────────────────────────────────────────────────────
function InputField({ id, label, type, value, onChange, placeholder, autoComplete }) {
  const [show, setShow] = useState(false);
  const isPassword = type === 'password';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <label htmlFor={id} style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
        {label}
      </label>
      <div style={{ position: 'relative' }}>
        <input
          id={id}
          type={isPassword && show ? 'text' : type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          autoComplete={autoComplete}
          style={{
            width: '100%', boxSizing: 'border-box',
            padding: isPassword ? '0.625rem 2.5rem 0.625rem 0.875rem' : '0.625rem 0.875rem',
            fontSize: 14, borderRadius: 8,
            border: '1.5px solid var(--border)',
            outline: 'none', color: 'var(--text-primary)',
            backgroundColor: 'var(--bg-surface)',
            transition: 'border-color 0.15s, box-shadow 0.15s',
          }}
          onFocus={e => {
            e.target.style.borderColor = 'var(--blue)';
            e.target.style.boxShadow = 'var(--shadow-focus)';
          }}
          onBlur={e => {
            e.target.style.borderColor = 'var(--border)';
            e.target.style.boxShadow = 'none';
          }}
        />
        {isPassword && (
          <button
            type="button"
            onClick={() => setShow(s => !s)}
            style={{
              position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 0,
            }}
          >
            {show ? <EyeOff size={16} /> : <Eye size={16} />}
          </button>
        )}
      </div>
    </div>
  );
}

// ── LoginSignup page ──────────────────────────────────────────────────────────
export default function LoginSignup({ onAuthSuccess }) {
  const [tab,      setTab]      = useState('login');   // 'login' | 'signup'
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm,  setConfirm]  = useState('');
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState('');

  const reset = () => { setError(''); setPassword(''); setConfirm(''); };
  const switchTab = (t) => { setTab(t); reset(); };

  const handleDemoLogin = async () => {
    setUsername('purva');
    setPassword('purva123');
    setError('');
    setLoading(true);
    try {
      const data = await authRequest('/auth/login', { username: 'purva', password: 'purva123' });
      localStorage.setItem('ipsec_token', data.token);
      localStorage.setItem('ipsec_user', data.username);
      onAuthSuccess(data.username, data.token);
    } catch (err) {
      setError(err.message || 'Demo login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!username.trim()) { setError('Username is required.'); return; }
    if (!password)         { setError('Password is required.'); return; }
    if (tab === 'signup') {
      if (password !== confirm) { setError('Passwords do not match.'); return; }
      if (password.length < 6)  { setError('Password must be at least 6 characters.'); return; }
    }

    setLoading(true);
    try {
      const endpoint = tab === 'login' ? '/auth/login' : '/auth/register';
      const data = await authRequest(endpoint, { username: username.trim(), password });
      localStorage.setItem('ipsec_token', data.token);
      localStorage.setItem('ipsec_user', data.username);
      onAuthSuccess(data.username, data.token);
    } catch (err) {
      setError(err.message || 'Something went wrong.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backgroundColor: 'var(--bg-page)',
      padding: '1.5rem',
      position: 'relative',
    }}>
      {/* Top right Theme toggle */}
      <div style={{ position: 'absolute', top: 20, right: 20 }}>
        <ThemeToggle />
      </div>

      <div style={{
        width: '100%', maxWidth: 420,
        backgroundColor: 'var(--bg-card)',
        borderRadius: 16,
        border: '1px solid var(--border)',
        boxShadow: 'var(--shadow-md)',
        padding: '2.5rem 2rem',
        display: 'flex', flexDirection: 'column', gap: '1.5rem',
      }}>

        {/* Brand */}
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
          <div style={{
            width: 54, height: 54, borderRadius: 12,
            backgroundColor: 'var(--blue-light)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            border: '1px solid var(--blue-border)',
            boxShadow: '0 2px 8px rgba(37,99,235,0.12)',
          }}>
            <Shield size={30} color="var(--blue)" />
          </div>
          <div style={{ textAlign: 'center' }}>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em' }}>
              IPsec VPN Analyzer
            </h1>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', margin: '4px 0 0' }}>
              AI-Powered Network Security Platform
            </p>
          </div>
        </div>

        {/* Tab switcher */}
        <div style={{
          display: 'flex', borderRadius: 8, border: '1px solid var(--border)',
          overflow: 'hidden', backgroundColor: 'var(--bg-surface)',
        }}>
          {['login', 'signup'].map(t => (
            <button key={t}
              id={`tab-${t}`}
              type="button"
              onClick={() => switchTab(t)}
              style={{
                flex: 1, padding: '0.55rem', border: 'none', cursor: 'pointer',
                fontSize: 13, fontWeight: 600,
                backgroundColor: tab === t ? 'var(--blue)' : 'transparent',
                color: tab === t ? '#FFFFFF' : 'var(--text-muted)',
                transition: 'all 0.15s',
                borderRadius: tab === t ? 6 : 0,
              }}
            >
              {t === 'login' ? 'Sign In' : 'Sign Up'}
            </button>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1.1rem' }}>

          <InputField
            id="username"
            label="Username"
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="Enter your username"
            autoComplete="username"
          />

          <InputField
            id="password"
            label="Password"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder={tab === 'signup' ? 'Min. 6 characters' : 'Enter your password'}
            autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
          />

          {tab === 'signup' && (
            <InputField
              id="confirm-password"
              label="Confirm Password"
              type="password"
              value={confirm}
              onChange={e => setConfirm(e.target.value)}
              placeholder="Re-enter your password"
              autoComplete="new-password"
            />
          )}

          {/* Error */}
          {error && (
            <div style={{
              display: 'flex', flexDirection: 'column', gap: 4,
              padding: '0.625rem 0.875rem', borderRadius: 8,
              backgroundColor: 'var(--red-light)', border: '1px solid var(--red-border)',
              color: 'var(--red)', fontSize: 13,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <AlertCircle size={15} style={{ flexShrink: 0 }} />
                <span style={{ fontWeight: 500 }}>{error}</span>
              </div>
              {tab === 'login' && error.includes('Invalid') && (
                <div style={{ fontSize: 12, paddingLeft: 23, color: 'var(--text-secondary)' }}>
                  Default password is <b>purva123</b>. You can also use <b>Quick Demo Sign In</b> below.
                </div>
              )}
            </div>
          )}

          {/* Submit */}
          <button
            id={`btn-${tab}-submit`}
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{
              width: '100%', padding: '0.75rem',
              justifyContent: 'center',
              fontSize: 14, fontWeight: 600, borderRadius: 8,
              marginTop: '0.25rem',
            }}
          >
            {loading
              ? <><Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} /> {tab === 'login' ? 'Signing in…' : 'Creating account…'}</>
              : tab === 'login' ? 'Sign In' : 'Create Account'
            }
          </button>

          {/* One-click Demo Login button */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '0.25rem 0' }}>
            <div style={{ flex: 1, height: 1, backgroundColor: 'var(--border)' }} />
            <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>or</span>
            <div style={{ flex: 1, height: 1, backgroundColor: 'var(--border)' }} />
          </div>

          <button
            id="btn-demo-login"
            type="button"
            onClick={handleDemoLogin}
            disabled={loading}
            style={{
              width: '100%', padding: '0.65rem',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              fontSize: 13, fontWeight: 600, borderRadius: 8,
              backgroundColor: 'var(--bg-surface)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border)',
              cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}
            onMouseOver={e => { e.currentTarget.style.borderColor = 'var(--blue)'; e.currentTarget.style.backgroundColor = 'var(--blue-light)'; }}
            onMouseOut={e => { e.currentTarget.style.borderColor = 'var(--border)'; e.currentTarget.style.backgroundColor = 'var(--bg-surface)'; }}
          >
            ⚡ Quick Demo Sign In (purva / purva123)
          </button>
        </form>

        <p style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-muted)', margin: 0 }}>
          Your data stays local. Analyses are stored in your own SQLite database.
        </p>
      </div>
    </div>
  );
}
