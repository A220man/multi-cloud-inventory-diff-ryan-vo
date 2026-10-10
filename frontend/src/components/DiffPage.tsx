import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { getDiff, type DiffResponse } from '../services/api';
import { BrainCircuit, ArrowLeft, CheckCircle } from 'lucide-react';

interface DiffPageProps {
  selectedDiffId: string | null;
  onNavigateToML: (diffId: string) => void;
}

export default function DiffPage({ selectedDiffId, onNavigateToML }: DiffPageProps) {
  const { token, hasRole } = useAuth();
  const [diff, setDiff] = useState<DiffResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedDiffId || !token) return;
    setLoading(true);
    setError(null);
    getDiff(selectedDiffId, token)
      .then(setDiff)
      .catch(err => setError(err instanceof Error ? err.message : 'Failed to load diff'))
      .finally(() => setLoading(false));
  }, [selectedDiffId, token]);

  if (!selectedDiffId) {
    return (
      <div className="card">
        <div className="empty-state">
          <ArrowLeft size={40} color="var(--color-muted)" />
          <div style={{ fontWeight: '600', marginTop: '12x' }}>No diff selected</div>
          <div style={{ fontSize: '13px', color: 'var(--color-muted)', marginTop: '8px' }}>
            Select a diff from the Snapshots page to view comparison results.
          </div>
        </div>
      </div>
    );
  }

  if (loading) {
    return <div className="card"><div className="loading-spinner">Loading diff…</div></div>;
  }

  if (error) {
    return <div className="card"><div className="error-banner">{error}</div></div>;
  }

  return (
    <div className="card" style={{ padding: '20px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '20px', borderBottom: '1px solid var(--color-border)', paddingBottom: '12px' }}>
        <BrainCircuit size={20} />
        <h2 style={{ fontSize: '18px', fontWeight: '600' }}>Diff Inspector</h2>
        <span style={{ fontSize: '12px', color: 'var(--color-muted)', fontFamily: 'monospace' }}>
          {selectedDiffId.slice(0, 16)}…
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '20px' }}>
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--color-accent)' }}>{diff?.added_count ?? 0}</div>
          <div className="stat-label">Added</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--color-danger)' }}>{diff?.removed_count ?? 0}</div>
          <div className="stat-label">Removed</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--color-warning)' }}>{diff?.modified_count ?? 0}</div>
          <div className="stat-label">Modified</div>
        </div>
        <div className="stat-card">
          <div className="stat-value" style={{ color: 'var(--color-success)' }}>{(diff?.added_count ?? 0) + (diff?.removed_count ?? 0) + (diff?.modified_count ?? 0)}</div>
          <div className="stat-label">Total Changes</div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: '16px', marginTop: '20px' }}>
        <button className="btn-primary" onClick={() => onNavigateToML(selectedDiffId)} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <BrainCircuit size={16} /> Run ML Evaluation
        </button>
        {hasRole('admin') && (
          <button className="btn-secondary" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <CheckCircle size={16} /> Approve Diff
          </button>
        )}
      </div>

      {diff?.items && diff.items.length > 0 && (
        <div style={{ marginTop: '24px' }}>
          <h3 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>Top Changes</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {diff.items.slice(0, 5).map(item => (
              <div key={item.resource_id} style={{ padding: '12px', background: 'var(--color-surface)', borderRadius: '4px', border: '1px solid var(--color-border)', cursor: 'pointer' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ fontWeight: '500', fontSize: '13px' }}>{item.resource_name}</div>
                  <span className={`badge badge-${item.diff_type}`}>{item.diff_type}</span>
                </div>
                <div style={{ fontSize: '12px', color: 'var(--color-muted)', marginTop: '4px' }}>
                  {item.resource_type} • {item.cloud_provider} • {item.exposure_level} exposure
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}