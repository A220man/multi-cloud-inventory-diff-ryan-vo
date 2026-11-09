import { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { listSnapshots, listDiffs, generateComplianceBundle, verifyComplianceBundle } from '../services/api';
import type { SnapshotSummary, DiffSummary, ComplianceBundleRequest, ComplianceBundleResponse, ComplianceBundleVerifyRequest } from '../types';
import { FileText, Download, CheckCircle, XCircle, AlertCircle, Loader2, Shield, FileSpreadsheet } from 'lucide-react';

export default function ComplianceBundlePage() {
  const { token, hasRole } = useAuth();
  const [snapshots, setSnapshots] = useState<SnapshotSummary[]>([]);
  const [diffs, setDiffs] = useState<DiffSummary[]>([]);
  const [selectedSnapshotIds, setSelectedSnapshotIds] = useState<string[]>([]);
  const [selectedDiffIds, setSelectedDiffIds] = useState<string[]>([]);
  const [description, setDescription] = useState('');
  const [includeMl, setIncludeMl] = useState(true);
  const [includeOpa, setIncludeOpa] = useState(true);
  const [includeAudit, setIncludeAudit] = useState(true);
  const [signBundle, setSignBundle] = useState(true);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [result, setResult] = useState<ComplianceBundleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [verifyBundle, setVerifyBundle] = useState<Record<string, unknown> | null>(null);
  const [verifyResult, setVerifyResult] = useState<{ valid: boolean; verified_at: string } | null>(null);
  const [verifying, setVerifying] = useState(false);

  const loadData = async () => {
    if (!token) return;
    setLoading(true);
    try {
      const [snaps, diffList] = await Promise.all([
        listSnapshots(token),
        listDiffs(token),
      ]);
      setSnapshots(snaps);
      setDiffs(diffList);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadData(); }, [token]);

  const handleGenerate = async () => {
    if (!token || (selectedSnapshotIds.length === 0 && selectedDiffIds.length === 0)) {
      setError('Please select at least one snapshot or diff');
      return;
    }
    setGenerating(true);
    setError(null);
    setResult(null);
    try {
      const payload: ComplianceBundleRequest = {
        snapshot_ids: selectedSnapshotIds,
        diff_ids: selectedDiffIds,
        description,
        include_ml: includeMl,
        include_opa: includeOpa,
        include_audit: includeAudit,
        sign_bundle: signBundle,
      };
      const response = await generateComplianceBundle(payload, token);
      setResult(response);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Generation failed');
    } finally {
      setGenerating(false);
    }
  };

  const handleVerify = async () => {
    if (!token || !verifyBundle) {
      setError('Please paste a bundle to verify');
      return;
    }
    setVerifying(true);
    setVerifyResult(null);
    try {
      const payload: ComplianceBundleVerifyRequest = { bundle: verifyBundle };
      const response = await verifyComplianceBundle(payload, token);
      setVerifyResult({ valid: response.valid, verified_at: response.verified_at });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const downloadCsv = (csvContent: string, filename: string) => {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  const downloadJson = (jsonContent: unknown, filename: string) => {
    const blob = new Blob([JSON.stringify(jsonContent, null, 2)], { type: 'application/json;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
  };

  if (loading) {
    return <div style={{ padding: '24px', textAlign: 'center' }}><Loader2 className="animate-spin" size={32} style={{ margin: '0 auto' }} /></div>;
  }

  return (
    <div style={{ padding: '24px', maxWidth: '1200px', margin: '0 auto' }}>
      <h1 style={{ marginBottom: '24px', fontSize: '28px', fontWeight: 600 }}>
        <Shield className="inline mr-2" size={28} /> Compliance Audit Bundles
      </h1>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
        {/* Generation Panel */}
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px', padding: '24px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '16px' }}>Generate Bundle</h2>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontWeight: 500, marginBottom: '8px' }}>Snapshots</label>
            <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid #e5e7eb', borderRadius: '6px' }}>
              {snapshots.length === 0 ? (
                <div style={{ padding: '16px', textAlign: 'center', color: '#6b7280' }}>No snapshots available</div>
              ) : (
                snapshots.map(snap => (
                  <label key={snap.id} style={{ display: 'flex', alignItems: 'center', padding: '10px 12px', borderBottom: '1px solid #f3f4f6', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={selectedSnapshotIds.includes(snap.id)}
                      onChange={(e) => setSelectedSnapshotIds(e.target.checked ? [...selectedSnapshotIds, snap.id] : selectedSnapshotIds.filter(id => id !== snap.id))}
                      style={{ marginRight: '10px', width: '16px', height: '16px' }}
                    />
                    <div>
                      <div style={{ fontWeight: 500 }}>{snap.name}</div>
                      <div style={{ fontSize: '12px', color: '#6b7280' }}>
                        {snap.cloud_provider} • {snap.asset_count} assets • {new Date(snap.created_at).toLocaleDateString()}
                      </div>
                    </div>
                  </label>
                ))
              )}
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontWeight: 500, marginBottom: '8px' }}>Diffs</label>
            <div style={{ maxHeight: '200px', overflowY: 'auto', border: '1px solid #e5e7eb', borderRadius: '6px' }}>
              {diffs.length === 0 ? (
                <div style={{ padding: '16px', textAlign: 'center', color: '#6b7280' }}>No diffs available</div>
              ) : (
                diffs.map(diff => (
                  <label key={diff.id} style={{ display: 'flex', alignItems: 'center', padding: '10px 12px', borderBottom: '1px solid #f3f4f6', cursor: 'pointer' }}>
                    <input
                      type="checkbox"
                      checked={selectedDiffIds.includes(diff.id)}
                      onChange={(e) => setSelectedDiffIds(e.target.checked ? [...selectedDiffIds, diff.id] : selectedDiffIds.filter(id => id !== diff.id))}
                      style={{ marginRight: '10px', width: '16px', height: '16px' }}
                    />
                    <div>
                      <div style={{ fontWeight: 500 }}>{diff.base_snapshot_id.slice(0,8)} → {diff.target_snapshot_id.slice(0,8)}</div>
                      <div style={{ fontSize: '12px', color: '#6b7280' }}>
                        +{diff.added_count} -{diff.removed_count} ~{diff.modified_count} • {new Date(diff.created_at).toLocaleDateString()}
                      </div>
                    </div>
                  </label>
                ))
              )}
            </div>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'block', fontWeight: 500, marginBottom: '8px' }}>Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional description for this compliance bundle"
              rows={3}
              style={{ width: '100%', padding: '10px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '14px', fontFamily: 'inherit', boxSizing: 'border-box' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', marginBottom: '20px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={includeMl} onChange={(e) => setIncludeMl(e.target.checked)} />
              <span>Include ML Evaluations</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={includeOpa} onChange={(e) => setIncludeOpa(e.target.checked)} />
              <span>Include OPA Violations</span>
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={includeAudit} onChange={(e) => setIncludeAudit(e.target.checked)} />
              <span>Include Audit Logs</span>
            </label>
          </div>

          <div style={{ marginBottom: '20px' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={signBundle} onChange={(e) => setSignBundle(e.target.checked)} />
              <span>Sign bundle (requires operator role)</span>
            </label>
          </div>

          <button
            onClick={handleGenerate}
            disabled={generating || (selectedSnapshotIds.length === 0 && selectedDiffIds.length === 0) || !hasRole('operator')}
            style={{
              width: '100%', padding: '12px', background: '#2563eb', color: '#fff',
              border: 'none', borderRadius: '6px', fontSize: '16px', fontWeight: 500,
              cursor: generating || (selectedSnapshotIds.length === 0 && selectedDiffIds.length === 0) || !hasRole('operator') ? 'not-allowed' : 'pointer',
              opacity: generating || (selectedSnapshotIds.length === 0 && selectedDiffIds.length === 0) || !hasRole('operator') ? 0.6 : 1,
            }}
          >
            {generating ? <Loader2 className="inline animate-spin mr-2" size={18} /> : ''}
            Generate Compliance Bundle
          </button>

          {error && (
            <div style={{ marginTop: '16px', padding: '12px', background: '#fef2f2', border: '1px solid #fecaca', borderRadius: '6px', color: '#dc2626', fontSize: '14px' }}>
              <XCircle className="inline mr-1" size={16} /> {error}
            </div>
          )}
        </div>

        {/* Results Panel */}
        <div style={{ background: '#fff', border: '1px solid #e5e7eb', borderRadius: '8px', padding: '24px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '16px' }}>Generated Bundle</h2>

          {result ? (
            <div>
              <div style={{ marginBottom: '16px', padding: '12px', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div style={{ fontWeight: 600 }}>Bundle Generated Successfully</div>
                  <span style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '14px', color: result.signed ? '#166534' : '#854d0e' }}>
                    {result.signed ? (
                      <>
                        <CheckCircle className="inline" size={16} /> Signed
                      </>
                    ) : (
                      <>
                        <AlertCircle className="inline" size={16} /> Unsigned (Demo)
                      </>
                    )}
                  </span>
                </div>
                <div style={{ fontSize: '13px', color: '#6b7280' }}>
                  <div>Bundle ID: <code>{result.bundle_id}</code></div>
                  <div>Created: {new Date(result.created_at).toLocaleString()}</div>
                  <div>Snapshots: {(result.bundle.snapshots as unknown[])?.length || 0} • Diffs: {(result.bundle.diffs as unknown[])?.length || 0}</div>
                </div>
              </div>

              <div style={{ marginBottom: '16px' }}>
                <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>JSON-LD Bundle</h3>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '8px' }}>
                  <button
                    onClick={() => downloadJson(result.bundle, `compliance-bundle-${result.bundle_id.slice(0,8)}.jsonld`)}
                    style={{ padding: '8px 16px', background: '#2563eb', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '13px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <Download className="inline" size={14} /> Download JSON-LD
                  </button>
                  <button
                    onClick={() => navigator.clipboard.writeText(JSON.stringify(result.bundle, null, 2))}
                    style={{ padding: '8px 16px', background: '#374151', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '13px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
                  >
                    <FileText className="inline" size={14} /> Copy to Clipboard
                  </button>
                </div>
                <details style={{ border: '1px solid #e5e7eb', borderRadius: '6px', overflow: 'hidden' }}>
                  <summary style={{ padding: '12px', background: '#f9fafb', cursor: 'pointer', fontSize: '13px', fontWeight: 500 }}>Preview (first 2000 chars)</summary>
                  <pre style={{ padding: '12px', maxHeight: '300px', overflow: 'auto', fontSize: '11px', background: '#1e1e1e', color: '#d4d4d4', margin: 0 }}>
                    {JSON.stringify(result.bundle, null, 2).slice(0, 2000)}...
                  </pre>
                </details>
              </div>

              {(() => {
                const csvExports = result.csv_exports || {};
                return Object.keys(csvExports).length > 0 ? (
                  <div style={{ marginBottom: '16px' }}>
                    <h3 style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px' }}>CSV Exports</h3>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                      {Object.entries(csvExports).map(([filename, content]) => (
                        <button
                          key={filename}
                          onClick={() => downloadCsv(content, filename)}
                          style={{ padding: '8px 16px', background: '#059669', color: '#fff', border: 'none', borderRadius: '4px', fontSize: '13px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px' }}
                        >
                          <FileSpreadsheet className="inline" size={14} /> {filename}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : null;
              })()}

            </div>
          ) : (
            <div style={{ textAlign: 'center', padding: '40px', color: '#9ca3af' }}>
              <FileText className="inline mx-auto mb-4" size={48} />
              <p>Generate a compliance bundle to see results here</p>
            </div>
          )}

          {/* Verification Section */}
          <div style={{ marginTop: '32px', paddingTop: '24px', borderTop: '1px solid #e5e7eb' }}>
            <h2 style={{ fontSize: '18px', fontWeight: 600, marginBottom: '16px' }}>Verify Bundle</h2>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontWeight: 500, marginBottom: '8px' }}>Paste JSON-LD Bundle</label>
              <textarea
                value={JSON.stringify(verifyBundle, null, 2)}
                onChange={(e) => {
                  try {
                    setVerifyBundle(JSON.parse(e.target.value));
                  } catch {
                    setVerifyBundle(null);
                  }
                }}
                placeholder='{"@context": [...], "type": [...], "metadata": {...}, "proof": {...}}'
                rows={8}
                style={{ width: '100%', padding: '10px', border: '1px solid #d1d5db', borderRadius: '6px', fontSize: '12px', fontFamily: 'monospace', boxSizing: 'border-box' }}
              />
            </div>
            <button
              onClick={handleVerify}
              disabled={verifying || !verifyBundle}
              style={{
                padding: '10px 20px', background: '#374151', color: '#fff', border: 'none', borderRadius: '6px',
                fontSize: '14px', fontWeight: 500, cursor: verifying || !verifyBundle ? 'not-allowed' : 'pointer',
                opacity: verifying || !verifyBundle ? 0.6 : 1,
              }}
            >
              {verifying ? <Loader2 className="inline animate-spin mr-2" size={16} /> : ''}
              Verify Signature
            </button>
            {verifyResult && (
              <div style={{ marginTop: '16px', padding: '16px', borderRadius: '6px', background: verifyResult.valid ? '#f0fdf4' : '#fef2f2', border: `1px solid ${verifyResult.valid ? '#bbf7d0' : '#fecaca'}` }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 600, color: verifyResult.valid ? '#166534' : '#dc2626' }}>
                  {verifyResult.valid ? <CheckCircle className="inline" size={20} /> : <XCircle className="inline" size={20} />}
                  {verifyResult.valid ? 'Signature Valid' : 'Signature Invalid'}
                </div>
                <div style={{ marginTop: '8px', fontSize: '13px', color: '#6b7280' }}>Verified at: {new Date(verifyResult.verified_at).toLocaleString()}</div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
