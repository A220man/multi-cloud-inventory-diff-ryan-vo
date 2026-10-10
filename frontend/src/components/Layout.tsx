import React from 'react';
import type { PageId } from '../App';
import { useAuth } from '../context/AuthContext';
import {
  LayoutDashboard,
  Database,
  GitCompareArrows,
  BrainCircuit,
  ScrollText,
  LogOut,
  Cloud,
} from 'lucide-react';

interface NavItem {
  id: PageId;
  label: string;
  icon: React.ReactNode;
  minRole?: 'viewer' | 'operator' | 'admin';
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={16} /> },
  { id: 'snapshots', label: 'Snapshots', icon: <Database size={16} /> },
  { id: 'diff', label: 'Diff Inspector', icon: <GitCompareArrows size={16} /> },
  { id: 'ml', label: 'ML Evaluation', icon: <BrainCircuit size={16} /> },
  { id: 'audit', label: 'Audit Log', icon: <ScrollText size={16} />, minRole: 'operator' },
];

interface LayoutProps {
  currentPage: PageId;
  onNavigate: (page: PageId) => void;
  children: React.ReactNode;
}

export default function Layout({ currentPage, onNavigate, children }: LayoutProps) {
  const { username, role, logout, hasRole } = useAuth();

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      <aside style={{
        width: '220px',
        background: 'var(--color-surface)',
        borderRight: '1px solid var(--color-border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>
        {/* Brand */}
        <div style={{
          padding: '18px 16px',
          borderBottom: '1px solid var(--color-border)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}>
          <Cloud size={20} color="var(--color-accent)" />
          <div>
            <div style={{ fontSize: '13px', fontWeight: '700', lineHeight: '1.2' }}>
              CloudInventory
            </div>
            <div style={{ fontSize: '10px', color: 'var(--color-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Diff & ML
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '10px 8px' }}>
          {NAV_ITEMS.filter(item => !item.minRole || hasRole(item.minRole)).map(item => (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                width: '100%',
                padding: '9px 12px',
                borderRadius: 'var(--radius-sm)',
                background: currentPage === item.id ? 'rgba(99,102,241,0.15)' : 'transparent',
                color: currentPage === item.id ? 'var(--color-accent-hover)' : 'var(--color-muted)',
                fontSize: '13px',
                fontWeight: currentPage === item.id ? '600' : '400',
                textAlign: 'left',
                marginBottom: '2px',
                transition: 'background 0.15s, color 0.15s',
              }}
              onMouseEnter={e => {
                if (currentPage !== item.id) {
                  (e.currentTarget as HTMLElement).style.background = 'rgba(99,102,241,0.07)';
                  (e.currentTarget as HTMLElement).style.color = 'var(--color-text)';
                }
              }}
              onMouseLeave={e => {
                if (currentPage !== item.id) {
                  (e.currentTarget as HTMLElement).style.background = 'transparent';
                  (e.currentTarget as HTMLElement).style.color = 'var(--color-muted)';
                }
              }}
            >
              {item.icon}
              {item.label}
            </button>
          ))}
        </nav>

        {/* User info + logout */}
        <div style={{
          padding: '14px 16px',
          borderTop: '1px solid var(--color-border)',
        }}>
          <div style={{ fontSize: '12px', color: 'var(--color-muted)', marginBottom: '4px' }}>
            Signed in as
          </div>
          <div style={{ fontSize: '13px', fontWeight: '600', marginBottom: '2px' }}>{username}</div>
          <div style={{ fontSize: '11px', color: 'var(--color-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px' }}>
            {role}
          </div>
          <button
            onClick={logout}
            className="btn-secondary"
            style={{ display: 'flex', alignItems: 'center', gap: '6px', width: '100%', fontSize: '12px' }}
          >
            <LogOut size={13} />
            Sign Out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main style={{
        flex: 1,
        overflow: 'auto',
        background: 'var(--color-bg)',
      }}>
        {children}
      </main>
    </div>
  );
}
