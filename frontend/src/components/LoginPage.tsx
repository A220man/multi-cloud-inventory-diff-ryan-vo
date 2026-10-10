import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { loginDemo } from '../services/api';
import type { UserRole } from '../types';
import { Cloud, Shield, BarChart2 } from 'lucide-react';

export default function LoginPage() {
  const { setAuth } = useAuth();
  const [role, setRole] = useState<UserRole>('operator');
  const [username, setUsername] = useState('demo-user');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const authState = await loginDemo({ role, username });
      setAuth(authState);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--color-bg)',
      padding: '20px',
    }}>
      <div style={{ width: '100%', maxWidth: '400px' }}>
        {/* Logo / Brand */}
        <div style={{ textAlign: 'center', marginBottom: '32px' }}>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginBottom: '12px' }}>
            <Cloud size={32} color="var(--color-aws)" />
            <Cloud size={32} color="var(--color-gcp)" />
            <Cloud size={32} color="var(--color-azure)" />
          </div>
          <h1 style={{ fontSize: '22px', fontWeight: '700', marginBottom: '6px' }}>
            Multi-Cloud Inventory Diff
          </h1>
          <p style={{ color: 'var(--color-muted)', fontSize: '13px' }}>
            AWS · GCP · Azure snapshot normalization, drift detection, and ML risk classification
          </p>
        </div>

        <div className="card">
          <div style={{
            background: 'rgba(99,102,241,0.1)',
            border: '1px solid rgba(99,102,241,0.3)',
            borderRadius: 'var(--radius-sm)',
            padding: '10px 14px',
            marginBottom: '20px',
            fontSize: '12px',
            color: 'var(--color-accent-hover)',
          }}>
            <strong>Local Demo Mode</strong> — Keycloak OIDC required in production.
            This endpoint is bound to localhost only and refuses to start in production.
          </div>

          {error && <div className="error-banner">{error}</div>}

          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="demo-user"
                style={{ width: '100%' }}
              />
            </div>

            <div className="form-group">
              <label>Role</label>
              <select
                value={role}
                onChange={e => setRole(e.target.value as UserRole)}
                style={{ width: '100%' }}
              >
                <option value="viewer">Viewer (read-only)</option>
                <option value="operator">Operator (create/run)</option>
                <option value="admin">Admin (full access)</option>
              </select>
            </div>

            <button
              type="submit"
              className="btn-primary"
              disabled={loading}
              style={{ width: '100%', padding: '10px', marginTop: '8px' }}
            >
              {loading ? 'Signing in…' : 'Sign In (Demo)'}
            </button>
          </form>

          <div style={{
            marginTop: '20px',
            paddingTop: '16px',
            borderTop: '1px solid var(--color-border)',
            display: 'flex',
            gap: '16px',
            fontSize: '12px',
            color: 'var(--color-muted)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Shield size={13} />
              <span>Keycloak OIDC + SAML</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <BarChart2 size={13} />
              <span>ML Drift Classifier</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
