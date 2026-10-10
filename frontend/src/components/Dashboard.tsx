import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { listSnapshots, seedSampleSnapshots, computeDiff, getMLBenchmark } from '../services/api';
import type { SnapshotSummary, MLBenchmarkResult } from '../types';
import { Cloud, BrainCircuit, AlertTriangle, RefreshCw, Zap, GitCompareArrows } from 'lucide-react';

interface DashboardProps {
  onNavigateToDiff: (diffId: string) => void;
}

export default function Dashboard({ onNavigateToDiff }: DashboardProps) {
  const { token, hasRole } = useAuth();
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [benchmark, setBenchmark] = useState<MLBenchmarkResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [seeding, setSeeding] = useState(false);
  const [diffing, setDiffing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadData = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const [snaps, bench] = await Promise.all([listSnapshots(token), getMLBenchmark(token)]);
      setSnapshots(snaps);
      setBenchmark(bench);
    } catch {
      // Handled gracefully
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, [token]);

  const handleSeed = async () => {
    if (!token) return;
    setSeeding(true);
    try {
      await seedSampleSnapshots(token);
      await loadData();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Seeding failed');
    } finally {
      setSeeding(false);
    }
  };

  const handleQuickDiff = async () => {
    if (!token || snapshots.length < 2) return;
    setDiffing(true);
    setError(null);
    try {
      const diff = await computeDiff(snapshots[0].id, snapshots[1].id, token);
      onNavigateToDiff(diff.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Diff failed');
    } finally {
      setDiffing(false);
    }
  };

  const totalAssets = snapshots.reduce((sum, s) => sum + s.asset_count, 0);
  const providerCount = new Set(snapshots.map(s => s.cloud_provider)).size;

  return (
    <div style={{ padding: '24px' }}>
      <div style={{ marginBottom: '20px' }}>
        <h1 style={{ fontSize: '20px', fontWeight: '700', marginBottom: '4px' }}>
          Multi-Cloud Inventory Dashboard
        </h1>
        <p style={{ color: 'var(--color-muted)', fontSize: '13px' }}>
          Normalize AWS/GCP/Azure asset exports, compare snapshots, and classify configuration drift with ML.
        </p>
      </div>

      <div style={{ display: 'flex', gap: '10px', marginBottom: '20px', flexWrap: 'wrap' }}>
        <button
          className="btn-primary"
          onClick={handleSeed}
          disabled={seeding || loading}
          style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <RefreshCw size={14} />
          {seeding ? 'Loading Sample Data...' : 'Load Sample Data'}
        </button>
        <button
          className="btn-secondary"
          onClick={handleQuickDiff}
          disabled={diffing || loading || snapshots.length < 2}
          style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <GitCompareArrows size={14} />
          {diffing ? 'Computing Diff...' : 'Quick Diff (First 2)'}
        </button>
        {error && <span style={{ color: 'var(--color-danger)', fontSize: '12px', alignSelf: 'center' }}>{error}</span>}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '14px', marginBottom: '20px' }}>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--color-muted)' }}>
            <Zap size={14} color="var(--color-aws)" /> Snapshots
          </div>
          <div style={{ fontSize: '24px', fontWeight: '700', marginTop: '4px' }}>{snapshots.length}</div>
        </div>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--color-muted)' }}>
            <Cloud size={14} color="var(--color-gcp)" /> Total Assets
          </div>
          <div style={{ fontSize: '24px', fontWeight: '700', marginTop: '4px' }}>{totalAssets}</div>
        </div>
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--color-muted)' }}>
            <AlertTriangle size={14} color="var(--color-warning)" /> Providers
          </div>
          <div style={{ fontSize: '24px', fontWeight: '700', marginTop: '4px' }}>{providerCount}</div>
        </div>
      </div>

      {benchmark && (
        <div className="card" style={{ marginBottom: '20px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <BrainCircuit size={16} color="var(--color-azure)" />
            <h2 style={{ fontSize: '14px', fontWeight: '600' }}>ML Classifier Benchmark (Offline)</h2>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px', marginBottom: '12px' }}>
            <div className="stat-card">
              <div className="stat-value">{(benchmark.model_metrics.accuracy * 100).toFixed(1)}%</div>
              <div className="stat-label">Accuracy</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{(benchmark.model_metrics.macro_f1 * 100).toFixed(1)}%</div>
              <div className="stat-label">Macro F1</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{(benchmark.model_metrics.macro_precision * 100).toFixed(1)}%</div>
              <div className="stat-label">Precision</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{benchmark.model_metrics.total_samples}</div>
              <div className="stat-label">Samples</div>
            </div>
          </div>
          <div style={{ fontSize: '11px', color: 'var(--color-muted)' }}>
            <strong>Command:</strong> <code>{benchmark.evaluation_command}</code> | <strong>Provenance:</strong> {benchmark.data_provenance}
          </div>
        </div>
      )}

      {snapshots.length > 0 ? (
        <div className="card">
          <h2 style={{ fontSize: '14px', fontWeight: '600', marginBottom: '12px' }}>Recent Snapshots</h2>
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Provider</th>
                <th>Assets</th>
                <th>Source</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {snapshots.slice(0, 5).map(s => (
                <tr key={s.id}>
                  <td style={{ fontWeight: '500' }}>{s.name}</td>
                  <td><span className={`badge badge-${s.cloud_provider}`}>{s.cloud_provider.toUpperCase()}</span></td>
                  <td>{s.asset_count}</td>
                  <td style={{ color: 'var(--color-muted)' }}>{s.source_type}</td>
                  <td style={{ color: 'var(--color-muted)', fontSize: '12px' }}>{new Date(s.created_at).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="card">
          <div className="empty-state">
            <AlertTriangle size={36} color="var(--color-muted)" />
            <div style={{ fontWeight: '600', marginTop: '6px' }}>No snapshots found</div>
            <div style={{ fontSize: '12px', marginTop: '2px' }}>
              {hasRole('operator') ? 'Click "Load Sample Data" to seed example multi-cloud snapshots.' : 'Ask an operator to create snapshots.'}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}