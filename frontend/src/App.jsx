import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useNavigate, useLocation } from 'react-router-dom';
import {
  Shield, LayoutDashboard, UploadCloud, History,
  Activity, XCircle, LogOut, User, ListChecks
} from 'lucide-react';
import { api, getToken, getUser, clearSession } from './lib/api';
import Dashboard from './pages/Dashboard';
import Upload from './pages/Upload';
import HistoryPage from './pages/HistoryPage';
import AnalysisDetail from './pages/AnalysisDetail';
import LoginSignup from './pages/LoginSignup';
import { ThemeProvider } from './context/ThemeContext';
import ThemeToggle from './components/ThemeToggle';
import SecurityRulesModal from './components/SecurityRulesModal';

const NAV = [
  { to: '/',        label: 'Overview',         icon: LayoutDashboard },
  { to: '/upload',  label: 'Analyze PCAP',     icon: UploadCloud },
  { to: '/history', label: 'Analysis History', icon: History },
];

function Sidebar({ username, onLogout, onOpenRules }) {
  return (
    <aside style={{
      width: 230,
      flexShrink: 0,
      display: 'flex',
      flexDirection: 'column',
      backgroundColor: 'var(--bg-card)',
      borderRight: '1px solid var(--border)',
      padding: '1.25rem 0',
      minHeight: '100vh',
      position: 'sticky',
      top: 0,
      alignSelf: 'flex-start',
    }} className="hidden lg:flex app-sidebar">
      
      {/* Logo / Brand */}
      <div style={{ padding: '0 1.25rem 1.25rem', borderBottom: '1px solid var(--border)', marginBottom: '0.875rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <div style={{
            width: 36, height: 36, borderRadius: 9,
            backgroundColor: 'var(--blue-light)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
            border: '1px solid var(--blue-border)',
          }}>
            <Shield style={{ width: 19, height: 19, color: 'var(--blue)' }} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.25 }}>
              IPsec VPN
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 500 }}>
              Protocol Analyzer
            </div>
          </div>
        </div>
      </div>

      {/* Nav items */}
      <nav style={{ padding: '0 0.75rem', flex: 1, display: 'flex', flexDirection: 'column', gap: '3px' }}>
        <div style={{ fontSize: '0.625rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', padding: '0 0.625rem', marginBottom: '0.5rem' }}>
          Main Navigation
        </div>
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
            <Icon style={{ width: 15, height: 15, flexShrink: 0 }} />
            {label}
          </NavLink>
        ))}

        <div style={{ fontSize: '0.625rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)', padding: '0 0.625rem', marginTop: '1rem', marginBottom: '0.5rem' }}>
          Knowledge & Compliance
        </div>
        <button
          type="button"
          onClick={onOpenRules}
          className="nav-item"
          style={{ width: '100%', border: 'none', background: 'transparent', textAlign: 'left', cursor: 'pointer' }}
        >
          <ListChecks style={{ width: 15, height: 15, flexShrink: 0 }} />
          Security Rules Catalog
        </button>
      </nav>

      {/* User + Logout */}
      <div style={{ padding: '1rem 1.25rem 0', borderTop: '1px solid var(--border)', marginTop: '1rem' }}>
        {username && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
            <div style={{
              width: 26, height: 26, borderRadius: '50%',
              backgroundColor: 'var(--blue-light)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <User size={13} style={{ color: 'var(--blue)' }} />
            </div>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {username}
            </span>
          </div>
        )}
        <button
          id="btn-logout"
          onClick={onLogout}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            width: '100%', padding: '0.45rem 0.5rem', border: 'none',
            borderRadius: 6, backgroundColor: 'transparent', cursor: 'pointer',
            fontSize: 12, color: 'var(--text-muted)', fontWeight: 500,
            transition: 'all 0.15s ease',
          }}
          onMouseOver={e => { e.currentTarget.style.backgroundColor = 'var(--red-light)'; e.currentTarget.style.color = 'var(--red)'; }}
          onMouseOut={e => { e.currentTarget.style.backgroundColor = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)'; }}
        >
          <LogOut size={13} />
          Sign out
        </button>
        <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6, marginTop: 10, marginBottom: 0 }}>
          IPsec VPN Analyzer<br />
          <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>v2.0 · AI XAI Engine</span>
        </p>
      </div>
    </aside>
  );
}

function TopBar({ backendOk, username, onLogout, onOpenRules }) {
  const navigate = useNavigate();
  return (
    <header className="lg:hidden" style={{
      position: 'sticky', top: 0, zIndex: 50,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0.75rem 1rem',
      backgroundColor: 'var(--bg-card)',
      borderBottom: '1px solid var(--border)',
    }}>
      <button onClick={() => navigate('/')} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'none', border: 'none', cursor: 'pointer' }}>
        <div style={{ width: 28, height: 28, borderRadius: 6, backgroundColor: 'var(--blue-light)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield style={{ width: 14, height: 14, color: 'var(--blue)' }} />
        </div>
        <span style={{ fontWeight: 700, color: 'var(--text-primary)', fontSize: 13 }}>IPsec VPN</span>
      </button>

      <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
        <ThemeToggle style={{ padding: '0.35rem 0.5rem' }} />

        {NAV.map(({ to, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}
            style={{ padding: '0.375rem' }}>
            <Icon style={{ width: 15, height: 15 }} />
          </NavLink>
        ))}

        <button
          onClick={onOpenRules}
          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '0.375rem', color: 'var(--text-muted)' }}
          title="Security Rules Catalog"
        >
          <ListChecks size={15} />
        </button>

        <button
          id="btn-logout-mobile"
          onClick={onLogout}
          style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '0.375rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}
          title={`Sign out (${username})`}
        >
          <LogOut size={15} />
        </button>
      </div>
    </header>
  );
}

function PageHeaderTitle() {
  const location = useLocation();
  const path = location.pathname;
  if (path === '/') return 'Security Overview';
  if (path === '/upload') return 'Analyze PCAP';
  if (path === '/history') return 'Analysis History';
  if (path.startsWith('/analysis/')) return 'Analysis Details';
  if (path === '/results') return 'Analysis Report';
  return 'Dashboard';
}

function AppShell({ username, onLogout }) {
  const [backendOk, setBackendOk] = useState(null);
  const [rulesOpen, setRulesOpen] = useState(false);

  useEffect(() => {
    api.health()
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));
  }, []);

  return (
    <div style={{ minHeight: '100vh', display: 'flex', backgroundColor: 'var(--bg-page)', color: 'var(--text-primary)' }}>

      {/* Desktop sidebar */}
      <Sidebar username={username} onLogout={onLogout} onOpenRules={() => setRulesOpen(true)} />

      {/* Main content area */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>

        {/* Mobile top bar */}
        <TopBar backendOk={backendOk} username={username} onLogout={onLogout} onOpenRules={() => setRulesOpen(true)} />

        {/* Desktop header bar */}
        <div className="hidden lg:flex app-header" style={{
          alignItems: 'center', justifyContent: 'space-between',
          padding: '0.75rem 2rem',
          backgroundColor: 'var(--bg-card)',
          borderBottom: '1px solid var(--border)',
        }}>
          {/* Section Breadcrumb / Title */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              <PageHeaderTitle />
            </span>
          </div>

          {/* Right Header items */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            {/* Theme Toggle Button */}
            <ThemeToggle />

            {/* Backend status badge */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 11, fontWeight: 500,
              padding: '4px 10px', borderRadius: 9999,
              backgroundColor: backendOk === true ? 'var(--green-light)' : backendOk === false ? 'var(--red-light)' : 'var(--bg-surface)',
              color: backendOk === true ? 'var(--green-text)' : backendOk === false ? 'var(--red-text)' : 'var(--text-muted)',
              border: `1px solid ${backendOk === true ? 'var(--green-border)' : backendOk === false ? 'var(--red-border)' : 'var(--border)'}`,
            }}>
              {backendOk === true ? (
                <>
                  <span style={{ position: 'relative', display: 'inline-flex', width: 7, height: 7 }}>
                    <span style={{
                      position: 'absolute', width: '100%', height: '100%',
                      borderRadius: '50%', backgroundColor: 'var(--green)',
                      animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite',
                      opacity: 0.5,
                    }} />
                    <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: 'var(--green)', display: 'block' }} />
                  </span>
                  Backend Online
                </>
              ) : backendOk === false ? (
                <><XCircle style={{ width: 10, height: 10 }} /> Backend Offline</>
              ) : (
                <><Activity style={{ width: 10, height: 10 }} /> Connecting…</>
              )}
            </div>

            {/* User badge */}
            {username && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, paddingLeft: 8, borderLeft: '1px solid var(--border)' }}>
                <div style={{
                  width: 26, height: 26, borderRadius: '50%',
                  backgroundColor: 'var(--blue-light)', display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <User size={13} style={{ color: 'var(--blue)' }} />
                </div>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{username}</span>
              </div>
            )}
          </div>
        </div>

        {/* Page content */}
        <main style={{ flex: 1, padding: '1.75rem 2rem', overflowY: 'auto' }} className="app-main">
          <Routes>
            <Route path="/"             element={<Dashboard />} />
            <Route path="/upload"       element={<Upload />} />
            <Route path="/history"      element={<HistoryPage />} />
            <Route path="/analysis/:id" element={<AnalysisDetail />} />
            <Route path="/results"      element={<AnalysisDetail />} />
          </Routes>
        </main>

        <footer style={{
          padding: '0.875rem 2rem',
          borderTop: '1px solid var(--border)',
          fontSize: 11,
          color: 'var(--text-muted)',
          textAlign: 'center',
          backgroundColor: 'var(--bg-card)',
        }} className="app-footer">
          IPsec VPN Protocol Analyzer © 2026 · Packet analysis powered by PyShark + TShark · ML by scikit-learn
        </footer>
      </div>

      {/* Security Rules Modal */}
      <SecurityRulesModal isOpen={rulesOpen} onClose={() => setRulesOpen(false)} />
    </div>
  );
}

function App() {
  const [username, setUsername] = useState(() => getUser());
  const [token,    setToken]    = useState(() => getToken());

  const handleAuthSuccess = (user, tok) => {
    setUsername(user);
    setToken(tok);
  };

  const handleLogout = async () => {
    const tok = getToken();
    if (tok) {
      try {
        await fetch(`${(import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '')}/api/auth/logout`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tok}` },
        });
      } catch {
        // Ignore
      }
    }
    clearSession();
    setUsername(null);
    setToken(null);
  };

  // Not logged in → show login page
  if (!token || !username) {
    return (
      <ThemeProvider>
        <LoginSignup onAuthSuccess={handleAuthSuccess} />
      </ThemeProvider>
    );
  }

  // Logged in → show full app
  return (
    <ThemeProvider>
      <BrowserRouter>
        <AppShell username={username} onLogout={handleLogout} />
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;

