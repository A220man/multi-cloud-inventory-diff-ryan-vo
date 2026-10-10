import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { listSnapshots, computeDiff, evaluateDiff, getMLBenchmark } from '../services/api';
import type { SnapshotSummary, MLEvaluationResponse, MLBenchmarkResult } from '../types';
import { BrainCircuit, RefreshCw } from 'lucide-react';

interface MLPageProps { selectedDiffId: string | null; }

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

export default function MLPage({ selectedDiffId: _selectedDiffId }: MLPageProps) {
  const { token, hasRole } = useAuth();
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [evaluation, setEvaluation] = useState<MLEvaluationResponse | null>(null);
  const [benchmark, setBenchmark] = useState<MLBenchmarkResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [baseId, setBaseId] = useState('');
  const [targetId, setTargetId] = useState('');
  const [anomalyThreshold, setAnomalyThreshold] = useState(0.7);
  const [tab, setTab] = useState<'evaluation' | 'benchmark'>('evaluation');

  useEffect(() => {
    if (!token) return;
    Promise.all([listSnapshots(token), getMLBenchmark(token)])
      .then(([snaps, bench]) => { setSnapshots(snaps); setBenchmark(bench); })
      .catch(() => {});
  }, [token]);

  const handleComputeAndEval = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token || !baseId || !targetId) return;
    setLoading(true); setError(null);
    try {
      const diff = await computeDiff(baseId, targetId, token);
      const ev = await evaluateDiff(diff.id, anomalyThreshold, token);
      setEvaluation(ev); setTab('evaluation');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Evaluation failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card" style={{ padding: '20px' }}>
      <div style={{ marginBottom: '16px' }}>
        <h1 style={{ fontSize: '18px', fontWeight: '600', marginBottom: '4px' }}>ML Drift Evaluation</h1>
        <p style={{ color: 'var(--color-muted)', fontSize: '12px' }}>Supervised severity classification with offline benchmark comparison.</p>
      </div>
      {error && <div className="error-banner">{error}</div>}
      <div style={{ display: 'flex', gap: '4px', marginBottom: '16px', borderBottom: '1px solid var(--color-border)' }}>
        {(['evaluation', 'benchmark'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              padding: '6px 12px',
              borderRadius: '0',
              borderBottom: tab === t ? '2px solid var(--color-accent)' : '2px solid transparent',
              fontWeight: tab === t ? '600' : '400',
              fontSize: '12px',
            }}
          >
            {t === 'evaluation' ? 'Run Evaluation' : 'Offline Benchmark'}
          </button>
        ))}
      </div>

      {tab === 'evaluation' && hasRole('operator') && (
        <div style={{ marginBottom: '16px' }}>
          <h2 style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px' }}>Compute Diff + Classify</h2>
          <form onSubmit={handleComputeAndEval}>
            <div style={{ display: 'grid', gap: '8px', marginBottom: '8px' }}>
              <div>
                <label style={{ fontSize: '11px', display: 'block' }}>Base Snapshot</label>
                <select value={baseId} onChange={e => setBaseId(e.target.value)} style={{ width: '100%' }}>
                  <option value="">Select base…</option>
                  {snapshots.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
              <div>
                <label style={{ fontSize: '11px', display: 'block' }}>Target Snapshot</label>
                <select value={targetId} onChange={e => setTargetId(e.target.value)} style={{ width: '100%' }}>
                  <option value="">Select target…</option>
                  {snapshots.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
                </select>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <label style={{ fontSize: '11px' }}>Threshold {anomalyThreshold.toFixed(2)}</label>
                <input type="range" min="0" max="1" step="0.05" value={anomalyThreshold} onChange={e => setAnomalyThreshold(parseFloat(e.target.value))} style={{ width: '120px' }} />
                <button type="submit" disabled={!baseId || !targetId || baseId === targetId || loading} style={{ fontSize: '12px' }}>
                  {loading ? 'Classifying…' : 'Run ML Evaluation'}
                </button>
              </div>
            </div>
            {loading && <div style={{ fontSize: '12px', color: 'var(--color-muted)' }}><RefreshCw size={12} /> Running evaluation…</div>}
          </form>
        </div>
      )}

      {tab === 'evaluation' && evaluation && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ display: 'flex', gap: '16px', marginBottom: '12px', fontSize: '12px' }}>
            <span>Evaluated: <strong>{evaluation.total_evaluated}</strong></span>
            <span>Critical: <strong style={{ color: 'var(--color-danger)' }}>{evaluation.critical_risk_count}</strong></span>
            <span>High: <strong>{evaluation.high_risk_count}</strong></span>
            <span>Anomalies: <strong>{evaluation.anomaly_count}</strong></span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Resource</th>
                <th>Type</th>
                <th>Provider</th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Anomaly</th>
              </tr>
            </thead>
            <tbody>
              {evaluation.evaluations.sort((a, b) => SEVERITY_ORDER.indexOf(a.predicted_severity) - SEVERITY_ORDER.indexOf(b.predicted_severity)).map(ev => (
                <tr key={ev.resource_id}>
                  <td style={{ fontWeight: '500' }}>{ev.resource_name}</td>
                  <td>{ev.resource_type}</td>
                  <td><span className={`badge badge-${ev.cloud_provider}`}>{ev.cloud_provider.toUpperCase()}</span></td>
                  <td><span className={`badge badge-${ev.predicted_severity}`}>{ev.predicted_severity}</span></td>
                  <td>{(ev.confidence * 100).toFixed(0)}%</td>
                  <td>{ev.anomaly_score.toFixed(2)}{ev.anomaly_score >= anomalyThreshold ? ' ⚠' : ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'evaluation' && !evaluation && !loading && (
        <div className="empty-state">
          <BrainCircuit size={30} color="var(--color-muted)" />
          <div style={{ fontWeight: '600', marginTop: '4px' }}>No evaluation yet</div>
          <div style={{ fontSize: '12px', color: 'var(--color-muted)' }}>Select snapshots and run ML evaluation.</div>
        </div>
      )}

      {tab === 'benchmark' && (
        <div style={{ marginTop: '16px' }}>
          <div style={{ fontSize: '13px', fontWeight: '600', marginBottom: '8px' }}>Offline Benchmark Results</div>
          {benchmark ? (
            <div style={{ display: 'grid', gap: '8px', fontSize: '12px' }}>
              <div><strong>Provenance:</strong> {benchmark.data_provenance}</div>
              <div>Dataset: {benchmark.dataset_size} samples</div>
              <div>Accuracy: {(benchmark.model_metrics.accuracy * 100).toFixed(1)}%</div>
              <div>Macro F1: {(benchmark.model_metrics.macro_f1 * 100).toFixed(1)}%</div>
              <div style={{ marginTop: '8px' }}>
                <strong>Failure Cases:</strong>
                {benchmark.failure_cases.map((fc, i) => <div key={i} style={{ color: 'var(--color-muted)', fontSize: '11px', marginTop: '2px' }}>{fc}</div>)}
              </div>
            </div>
          ) : (
            <div className="empty-state">Benchmark data unavailable.</div>
          )}
        </div>
      )}
    </div>
  );
}