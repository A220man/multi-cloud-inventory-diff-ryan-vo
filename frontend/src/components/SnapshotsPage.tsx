import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { listSnapshots, deleteSnapshot, computeDiff, listDiffs, type SnapshotSummary, type DiffSummary } from '../services/api';
import { GitCompareArrows, History } from 'lucide-react';

interface SnapshotsPageProps {
  onNavigateToDiff: (diffId: string) => void;
}

export default function SnapshotsPage({ onNavigateToDiff }: SnapshotsPageProps) {
  const { token, hasRole } = useAuth();
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [diffs, setDiffs] = useState<DiffSummary[]>([]);
  const [baseId, setBaseId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [loading, setLoading] = useState(true);
  const [diffing, setDiffing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const [snaps, history] = await Promise.all([listSnapshots(token), listDiffs(token)]);
      setSnapshots(snaps);
      setDiffs(history);
      if (snaps.length >= 2) {
        setBaseId(p => p || snaps[0].id);
        setTargetId(p => p || snaps[1].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, [token]);

  const handleCompare = async () => {
    if (!token || !baseId || !targetId) return;
    if (baseId === targetId) {
      setError('Base and target snapshots must be distinct.');
      return;
    }
    setDiffing(true);
    setError(null);
    try {
      const res = await computeDiff(baseId, targetId, token);
      onNavigateToDiff(res.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Diff failed');
    } finally {
      setDiffing(false);
    }
  };

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Delete snapshot?')) return;
    try {
      await deleteSnapshot(id, token!);
      setSnapshots(snapshots.filter(s => s.id !== id));
      if (baseId === id) setBaseId('');
      if (targetId === id) setTargetId('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  if (loading) return <div className="card"><div className="loading-spinner">Loading…</div></div>;

  if (snapshots.length === 0) {
    return (
      <div className="card">
        <div className="empty-state">
          <div style={{ fontWeight: '600' }}>No snapshots yet</div>
          <div style={{ fontSize: '13px', color: 'var(--color-muted)', marginTop: '8px' }}>
            Import asset exports or load sample data on the dashboard.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {error && <div className="card"><div className="error-banner">{error}</div></div>}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <GitCompareArrows size={18} />
          <strong>Snapshot Pair Comparator</strong>
        </div>
        <p style={{ fontSize: '13px', color: 'var(--color-muted)', marginBottom: '12px' }}>
          Compare any baseline and drifted snapshot to compute field deltas and ML risk scores.
        </p>
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 1, minWidth: '180px' }}>
            <label htmlFor="base-snapshot-select" style={{ fontSize: '12px', display: 'block', marginBottom: '4px' }}>Base:</label>
            <select id="base-snapshot-select" value={baseId} onChange={e => setBaseId(e.target.value)} style={{ width: '100%' }}>
              {snapshots.map(s => <option key={s.id} value={s.id}>{s.name} ({s.cloud_provider.toUpperCase()})</option>)}
            </select>
          </div>
          <div style={{ flex: 1, minWidth: '180px' }}>
            <label htmlFor="target-snapshot-select" style={{ fontSize: '12px', display: 'block', marginBottom: '4px' }}>Target:</label>
            <select id="target-snapshot-select" value={targetId} onChange={e => setTargetId(e.target.value)} style={{ width: '100%' }}>
              {snapshots.map(s => <option key={s.id} value={s.id}>{s.name} ({s.cloud_provider.toUpperCase()})</option>)}
            </select>
          </div>
          <button className="btn-primary" onClick={handleCompare} disabled={diffing || !baseId || !targetId || baseId === targetId}>
            {diffing ? 'Computing…' : 'Compare Snapshots'}
          </button>
        </div>
      </div>

      <div className="card" style={{ padding: 0 }}>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--color-border)' }}><strong>Inventory Snapshots</strong></div>
        <div style={{ overflow: 'auto' }}>
          <table>
            <thead><tr><th>Name</th><th>Provider</th><th>Type</th><th>Assets</th><th>Date</th><th>Pair Actions</th></tr></thead>
            <tbody>
              {snapshots.map(s => (
                <tr key={s.id}>
                  <td><strong>{s.name}</strong></td>
                  <td><span className={`badge badge-${s.cloud_provider}`}>{s.cloud_provider.toUpperCase()}</span></td>
                  <td style={{ fontSize: '11px', color: 'var(--color-muted)' }}>{s.source_type}</td>
                  <td>{s.asset_count}</td>
                  <td style={{ fontSize: '11px' }}>{new Date(s.created_at).toLocaleDateString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '4px' }}>
                      <button className="btn-secondary btn-xs" onClick={() => setBaseId(s.id)} disabled={baseId === s.id}>
                        {baseId === s.id ? 'Is Base' : 'Set Base'}
                      </button>
                      <button className="btn-secondary btn-xs" onClick={() => setTargetId(s.id)} disabled={targetId === s.id}>
                        {targetId === s.id ? 'Is Target' : 'Set Target'}
                      </button>
                      {hasRole('admin') && <button className="btn-danger btn-xs" onClick={e => handleDelete(s.id, e)}>Del</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {diffs.length > 0 && (
        <div className="card" style={{ padding: 0 }}>
          <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--color-border)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <History size={16} /><strong>Recent Comparison Runs</strong>
          </div>
          <div style={{ overflow: 'auto' }}>
            <table>
              <thead><tr><th>Diff ID</th><th>Base / Target</th><th>Changes</th><th>Date</th><th>Action</th></tr></thead>
              <tbody>
                {diffs.map(d => (
                  <tr key={d.id} style={{ cursor: 'pointer' }} onClick={() => onNavigateToDiff(d.id)}>
                    <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{d.id.slice(0, 8)}…</td>
                    <td style={{ fontSize: '12px' }}>{d.base_snapshot_id.slice(0, 8)} → {d.target_snapshot_id.slice(0, 8)}</td>
                    <td style={{ fontSize: '12px' }}>
                      <span style={{ color: 'var(--color-accent)' }}>+{d.added_count}</span>{' '}
                      <span style={{ color: 'var(--color-danger)' }}>-{d.removed_count}</span>{' '}
                      <span style={{ color: 'var(--color-warning)' }}>~{d.modified_count}</span>
                    </td>
                    <td style={{ fontSize: '11px' }}>{new Date(d.created_at).toLocaleDateString()}</td>
                    <td><button className="btn-secondary btn-xs" onClick={() => onNavigateToDiff(d.id)}>Inspect</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}