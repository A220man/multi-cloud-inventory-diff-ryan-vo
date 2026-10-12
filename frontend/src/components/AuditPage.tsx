import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { listAuditLogs } from '../services/api';
import type { AuditLogEntry } from '../types';
import { ScrollText, RefreshCw, ChevronDown, ChevronUp } from 'lucide-react';

export default function AuditPage() {
  const { token } = useAuth();
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);
  const [filterAction, setFilterAction] = useState('');
  const [filterResource, setFilterResource] = useState('');
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = async () => {
    if (!token) return;
    setLoading(true); setError(null);
    try {
      setEntries(await listAuditLogs(token, limit, offset, filterAction || undefined, filterResource || undefined));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [token, limit, offset, filterAction, filterResource]);

  const uniqueActions = [...new Set(entries.map(e => e.action))];

  return (
    <div style={{ padding: '20px' }}>
      <div style={{ marginBottom: '16px' }}>
        <h1 style={{ fontSize: '18px', fontWeight: '700', display: 'flex', alignItems: 'center', gap: '8px' }}>
          <ScrollText size={18} /> Audit Log
        </h1>
        <p style={{ color: 'var(--color-muted)', fontSize: '12px' }}>
          Immutable record of data-mutating operations with actor, role, and details.
        </p>
      </div>

      {error && <div className="card"><div className="error-banner">{error}</div></div>}

      <div className="card" style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <label style={{ fontSize: '11px', display: 'block' }}>Action</label>
            <select value={filterAction} onChange={e => { setFilterAction(e.target.value); setOffset(0); }}>
              <option value="">All actions</option>
              {uniqueActions.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: '11px', display: 'block' }}>Resource</label>
            <select value={filterResource} onChange={e => { setFilterResource(e.target.value); setOffset(0); }}>
              <option value="">All types</option>
              {['snapshot', 'diff', 'ml_evaluation', 'advisory'].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <div>
            <label style={{ fontSize: '11px', display: 'block' }}>Size</label>
            <select value={limit} onChange={e => { setLimit(parseInt(e.target.value)); setOffset(0); }}>
              {[25, 50, 100].map(n => <option key={n} value={n}>{n}</option>)}
            </select>
          </div>
          <button className="btn-secondary" onClick={load} disabled={loading} style={{ alignSelf: 'flex-end', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="card"><div className="loading-spinner" /></div>
      ) : entries.length === 0 ? (
        <div className="card">
          <div className="empty-state">
            <ScrollText size={32} color="var(--color-muted)" />
            <div style={{ fontWeight: '600', marginTop: '6px' }}>No audit entries</div>
          </div>
        </div>
      ) : (
        <>
          <div className="card" style={{ padding: 0 }}>
            <table>
              <thead>
                <tr><th>Time</th><th>Actor</th><th>Role</th><th>Action</th><th>Resource</th><th>Details</th></tr>
              </thead>
              <tbody>
                {entries.map(e => (
                  <React.Fragment key={e.id}>
                    <tr onClick={() => setExpanded(expanded === e.id ? null : e.id)} style={{ cursor: 'pointer' }}>
                      <td style={{ fontSize: '11px', color: 'var(--color-muted)' }}>{new Date(e.created_at).toLocaleString()}</td>
                      <td style={{ fontWeight: '500', fontSize: '12px' }}>{e.actor}</td>
                      <td><span className="badge">{e.role}</span></td>
                      <td><span style={{ fontSize: '11px', fontFamily: 'monospace' }}>{e.action}</span></td>
                      <td style={{ fontSize: '11px', color: 'var(--color-muted)' }}>{e.resource_type}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px', color: 'var(--color-muted)' }}>
                          {expanded === e.id ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                          {Object.keys(e.details).length} fields
                        </div>
                      </td>
                    </tr>
                    {expanded === e.id && (
                      <tr>
                        <td colSpan={6} style={{ background: 'var(--color-surface)', padding: '8px 14px', fontSize: '11px' }}>
                          {e.resource_id && <div><strong>ID: </strong><code>{e.resource_id}</code></div>}
                          {Object.entries(e.details).map(([k, v]) => (
                            <div key={k}><strong>{k}: </strong>{JSON.stringify(v)}</div>
                          ))}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button className="btn-secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>← Prev</button>
            <span style={{ fontSize: '12px', color: 'var(--color-muted)' }}>Showing {offset + 1}–{offset + entries.length}</span>
            <button className="btn-secondary" disabled={entries.length < limit} onClick={() => setOffset(offset + limit)}>Next →</button>
          </div>
        </>
      )}
    </div>
  );
}
