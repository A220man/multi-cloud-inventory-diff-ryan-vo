/**
 * Typed API client derived from backend route definitions.
 * All endpoints require Bearer token auth (retrieved from AuthContext).
 */
import type {
  SnapshotSummary, SnapshotDetail, SnapshotCreateRequest, DiffResponse,
  DiffSummary, MLEvaluationResponse, MLBenchmarkResult, LLMAdvisoryResponse,
  AuditLogEntry, SeedResponse, AuthState, DemoLoginRequest, LLMProvider, UserRole,
} from '../types';

const BASE = '/api';

class ApiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

async function request<T>(
  path: string,
  options: RequestInit = {},
  token?: string | null
): Promise<T> {
  const init: RequestInit = { ...options };

  if (token) {
    init.headers = init.headers ?? {};
    (init.headers as Record<string, string>)['Authorization'] = `Bearer ${token}`;
  }

  const res = await fetch(`${BASE}${path}`, init);

  if (!res.ok) {
    const errBody = await res.text();
    throw new ApiError(
      `API request failed ${res.status}: ${res.statusText} - ${errBody}`
    );
  }

  return (await res.json()) as T;
}

// ─── Auth ────────────────────────────────────────────────────────────────────
export async function loginDemo(payload: DemoLoginRequest): Promise<AuthState> {
  const data = await request<{ access_token: string; role: string; username: string; expires_in: number }>(
    '/auth/demo-token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) },
  );
  return { token: data.access_token, role: data.role as UserRole, username: data.username, isAuthenticated: true };
}

// ─── Health ───────────────────────────────────────────────────────────────────
export async function checkHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/health');
}

// ─── Snapshots ───────────────────────────────────────────────────────────────
export async function listSnapshots(token: string): Promise<SnapshotSummary[]> {
  return request<SnapshotSummary[]>('/snapshots', {}, token);
}

export async function getSnapshot(id: string, token: string): Promise<SnapshotDetail> {
  return request<SnapshotDetail>(`/snapshots/${id}`, {}, token);
}

export async function createSnapshot(
  payload: SnapshotCreateRequest,
  token: string
): Promise<SnapshotSummary> {
  return request<SnapshotSummary>('/snapshots', { method: 'POST', body: JSON.stringify(payload) }, token);
}

export async function deleteSnapshot(id: string, token: string): Promise<void> {
  return request<void>(`/snapshots/${id}`, { method: 'DELETE' }, token);
}

export async function seedSampleSnapshots(token: string): Promise<SeedResponse> {
  return request<SeedResponse>('/snapshots/sample-seed', { method: 'POST' }, token);
}

// ─── Diffs ───────────────────────────────────────────────────────────────────
export async function computeDiff(
  baseSnapshotId: string,
  targetSnapshotId: string,
  token: string
): Promise<DiffResponse> {
  return request<DiffResponse>('/diffs', { method: 'POST', body: JSON.stringify({ base_snapshot_id: baseSnapshotId, target_snapshot_id: targetSnapshotId }) }, token);
}

export async function getDiff(id: string, token: string): Promise<DiffResponse> {
  return request<DiffResponse>(`/diffs/${id}`, {}, token);
}

export async function listDiffs(
  token: string,
  snapshotId?: string,
  limit = 50,
  offset = 0
): Promise<DiffSummary[]> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    ...(snapshotId ? { snapshot_id: snapshotId } : {}),
  });
  return request<DiffSummary[]>(`/diffs?${params.toString()}`, {}, token);
}

// ─── ML Evaluation ───────────────────────────────────────────────────────────
export async function evaluateDiff(
  diffId: string,
  anomalyThreshold: number,
  token: string
): Promise<MLEvaluationResponse> {
  return request<MLEvaluationResponse>('/ml/evaluate', { method: 'POST', body: JSON.stringify({ diff_id: diffId, anomaly_threshold: anomalyThreshold }) }, token);
}

export async function getMLBenchmark(token: string): Promise<MLBenchmarkResult> {
  return request<MLBenchmarkResult>('/ml/benchmark', {}, token);
}

// ─── LLM Advisory ────────────────────────────────────────────────────────────
export async function generateAdvisory(
  diffId: string,
  provider: LLMProvider | undefined,
  token: string
): Promise<LLMAdvisoryResponse> {
  return request<LLMAdvisoryResponse>('/advisory/generate', { method: 'POST', body: JSON.stringify({ diff_id: diffId, provider }) }, token);
}

// ─── Audit Log ───────────────────────────────────────────────────────────────
export async function listAuditLogs(
  token: string,
  limit = 50,
  offset = 0,
  action?: string,
  resourceType?: string
): Promise<AuditLogEntry[]> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
    ...(action ? { action } : {}),
    ...(resourceType ? { resourceType } : {}),
  });
  return request<AuditLogEntry[]>(`/audit?${params.toString()}`, { method: 'GET' }, token);
}

export { ApiError };

export type * from '../types';