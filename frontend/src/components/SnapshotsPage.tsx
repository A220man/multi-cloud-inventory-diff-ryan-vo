import React, { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { listSnapshots, deleteSnapshot, type SnapshotSummary } from '../services/api';

interface SnapshotsPageProps {
  onNavigateToDiff: (diffId: string) => void;
}

export default function SnapshotsPage({ onNavigateToDiff }: SnapshotsPageProps) {
  const { token, hasRole } = useAuth();
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    listSnapshots(token)
      .then(setSnapshots)
      .catch(err => setError(err instanceof Error ? err.message : 'Failed to load snapshots'))
      .finally(() => setLoading(false));
  }, [token]);

  const handleDelete = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Delete this snapshot?')) return;
    try {
      await deleteSnapshot(id, token!);
      setSnapshots(snapshots.filter(s => s.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete');
    }
  };

  if (loading) {
    return <div className="card"><div className="loading-spinner">Loading snapshots…</div></div>;
  }

  if (error) {
    return <div className="card"><div className="error-banner">{error}</div></div>;
  }

  if (snapshots.length === 0) {
    return (
      <div className="card">
        <div className="empty-state">
          <div style={{ fontWeight: '600' }}>No snapshots yet</div>
          <div style={{ fontSize: '13px', color: 'var(--color-muted)', marginTop: '8px' }}>
            Create a snapshot by importing a cloud provider asset export.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="card" style={{ padding: 0 }}>
      <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--color-border)' }}>
        <strong style={{ fontSize: '14px' }}>Snapshots</strong>
      </div>
      <div style={{ overflow: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Provider</th>
              <th>Type</th>
              <th>Assets</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {snapshots.map(s => (
              <tr key={s.id} style={{ cursor: 'pointer' }} onClick={() => onNavigateToDiff(s.id)}>
                <td><div style={{ fontWeight: '500', fontSize: '13px' }}>{s.name}</div></td>
                <td><span className={`badge badge-${s.cloud_provider}`}>{s.cloud_provider.toUpperCase()}</span></td>
                <td style={{ fontSize: '11px', color: 'var(--color-muted)' }}>{s.source_type}</td>
                <td style={{ fontSize: '13px' }}>{s.asset_count}</td>
                <td style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
                  {new Date(s.created_at).toLocaleDateString()}
                </td>
                <td onClick={e => handleDelete(s.id, e)}>
                  {hasRole('admin') && (
                    <button className="btn-danger" style={{ fontSize: '12px' }}>Delete</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}