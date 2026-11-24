import { Sun, Moon } from 'lucide-react';
import { useTheme } from '../context/ThemeContext';

export default function ThemeToggle({ className = '', style = {} }) {
  const { theme, toggleTheme, isDark } = useTheme();

  return (
    <button
      id="theme-toggle-btn"
      type="button"
      onClick={toggleTheme}
      title={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
      aria-label={isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
      className={`theme-toggle-btn ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '0.4rem',
        padding: '0.45rem 0.65rem',
        borderRadius: '8px',
        border: '1px solid var(--border)',
        backgroundColor: 'var(--bg-card)',
        color: 'var(--text-secondary)',
        cursor: 'pointer',
        fontSize: '12px',
        fontWeight: 500,
        transition: 'all 0.15s ease',
        ...style,
      }}
    >
      {isDark ? (
        <>
          <Sun size={15} style={{ color: '#F59E0B' }} />
          <span style={{ fontSize: 11, fontWeight: 600 }}>Light</span>
        </>
      ) : (
        <>
          <Moon size={15} style={{ color: '#6366F1' }} />
          <span style={{ fontSize: 11, fontWeight: 600 }}>Dark</span>
        </>
      )}
    </button>
  );
}

