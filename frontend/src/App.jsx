import { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom';
import {
  Shield, LayoutDashboard, UploadCloud, History,
  Activity, XCircle,
} from 'lucide-react';
import { api } from './lib/api';
import Dashboard     from './pages/Dashboard';
import Upload        from './pages/Upload';
import HistoryPage   from './pages/HistoryPage';
import AnalysisDetail from './pages/AnalysisDetail';

const NAV = [
  { to: '/',        label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/upload',  label: 'Analyze PCAP', icon: UploadCloud },
  { to: '/history', label: 'History',      icon: History },
];

function Sidebar() {
  return (
    <aside style={{
      width: 220,
      flexShrink: 0,
      display: 'flex',
      flexDirection: 'column',
      backgroundColor: '#FFFFFF',
      borderRight: '1px solid #E2E8F0',
      padding: '1.5rem 0',
      minHeight: '100vh',
      position: 'sticky',
      top: 0,
      alignSelf: 'flex-start',
    }} className="hidden lg:flex">
      
      {/* Logo / Brand */}
      <div style={{ padding: '0 1.25rem 1.5rem', borderBottom: '1px solid #E2E8F0', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.625rem' }}>
          <div style={{
            width: 34, height: 34, borderRadius: 8,
            backgroundColor: '#EFF6FF',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Shield style={{ width: 18, height: 18, color: '#2563EB' }} />
          </div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#0F172A', lineHeight: 1.3 }}>
              IPsec VPN
            </div>
            <div style={{ fontSize: 11, color: '#64748B', fontWeight: 500 }}>
              Analyzer
            </div>
          </div>
        </div>
      </div>

      {/* Nav items */}
      <nav style={{ padding: '0 0.75rem', flex: 1, display: 'flex', flexDirection: 'column', gap: '2px' }}>
        <div style={{ fontSize: '0.6rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', color: '#94A3B8', padding: '0 0.625rem', marginBottom: '0.5rem' }}>
          Navigation
        </div>
        {NAV.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
            <Icon style={{ width: 15, height: 15, flexShrink: 0 }} />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer version */}
      <div style={{ padding: '1rem 1.25rem 0', borderTop: '1px solid #E2E8F0', marginTop: '1rem' }}>
        <p style={{ fontSize: 11, color: '#94A3B8', lineHeight: 1.6 }}>
          IPsec VPN Analyzer<br />
          <span style={{ color: '#CBD5E1' }}>v2.0 · AI-Powered</span>
        </p>
      </div>
    </aside>
  );
}

function TopBar({ backendOk }) {
  const navigate = useNavigate();
  return (
    <header className="lg:hidden" style={{
      position: 'sticky', top: 0, zIndex: 50,
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0.75rem 1rem',
      backgroundColor: '#FFFFFF',
      borderBottom: '1px solid #E2E8F0',
    }}>
      <button onClick={() => navigate('/')} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'none', border: 'none', cursor: 'pointer' }}>
        <div style={{ width: 28, height: 28, borderRadius: 6, backgroundColor: '#EFF6FF', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Shield style={{ width: 14, height: 14, color: '#2563EB' }} />
        </div>
        <span style={{ fontWeight: 700, color: '#0F172A', fontSize: 13 }}>IPsec VPN Analyzer</span>
      </button>
      <nav style={{ display: 'flex', gap: '4px' }}>
        {NAV.map(({ to, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}
            style={{ padding: '0.375rem' }}>
            <Icon style={{ width: 15, height: 15 }} />
          </NavLink>
        ))}
      </nav>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 6,
        fontSize: 11, fontWeight: 500,
        padding: '3px 10px', borderRadius: 9999,
        backgroundColor: backendOk ? '#F0FDF4' : '#FEF2F2',
        color: backendOk ? '#15803D' : '#B91C1C',
        border: `1px solid ${backendOk ? '#BBF7D0' : '#FECACA'}`,
      }}>
        {backendOk
          ? <><span style={{ width: 6, height: 6, borderRadius: '50%', backgroundColor: '#16A34A', display: 'inline-block' }} />Online</>
          : <><XCircle style={{ width: 10, height: 10 }} />Offline</>
        }
      </div>
    </header>
  );
}

function App() {
  const [backendOk, setBackendOk] = useState(null);

  useEffect(() => {
    api.health()
      .then(() => setBackendOk(true))
      .catch(() => setBackendOk(false));
  }, []);

  return (
    <BrowserRouter>
      <div style={{ minHeight: '100vh', display: 'flex', backgroundColor: '#F5F7FA', color: '#0F172A' }}>

        {/* Desktop sidebar */}
        <Sidebar />

        {/* Main content area */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>

          {/* Mobile top bar */}
          <TopBar backendOk={backendOk} />

          {/* Desktop header bar */}
          <div className="hidden lg:flex" style={{
            alignItems: 'center', justifyContent: 'flex-end',
            padding: '0.625rem 1.75rem',
            backgroundColor: '#FFFFFF',
            borderBottom: '1px solid #E2E8F0',
          }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              fontSize: 11, fontWeight: 500,
              padding: '3px 10px', borderRadius: 9999,
              backgroundColor: backendOk === true  ? '#F0FDF4' : backendOk === false ? '#FEF2F2' : '#F8FAFC',
              color:           backendOk === true  ? '#15803D' : backendOk === false ? '#B91C1C' : '#64748B',
              border: `1px solid ${backendOk === true ? '#BBF7D0' : backendOk === false ? '#FECACA' : '#E2E8F0'}`,
            }}>
              {backendOk === true ? (
                <>
                  <span style={{ position: 'relative', display: 'inline-flex', width: 7, height: 7 }}>
                    <span style={{
                      position: 'absolute', width: '100%', height: '100%',
                      borderRadius: '50%', backgroundColor: '#16A34A',
                      animation: 'ping 2s cubic-bezier(0,0,0.2,1) infinite',
                      opacity: 0.5,
                    }} />
                    <span style={{ width: 7, height: 7, borderRadius: '50%', backgroundColor: '#16A34A', display: 'block' }} />
                  </span>
                  Backend Online
                </>
              ) : backendOk === false ? (
                <><XCircle style={{ width: 10, height: 10 }} /> Backend Offline</>
              ) : (
                <><Activity style={{ width: 10, height: 10 }} /> Connecting…</>
              )}
            </div>
          </div>

          {/* Page content */}
          <main style={{ flex: 1, padding: '1.75rem 2rem', overflowY: 'auto' }}>
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
            borderTop: '1px solid #E2E8F0',
            fontSize: 11,
            color: '#94A3B8',
            textAlign: 'center',
            backgroundColor: '#FFFFFF',
          }}>
            IPsec VPN Protocol Analyzer © 2026 · Packet analysis powered by PyShark + TShark · ML by scikit-learn
          </footer>
        </div>
      </div>
    </BrowserRouter>
  );
}

export default App;
