// TypeScript types derived from backend API schemas
export type CloudProvider = 'aws' | 'gcp' | 'azure' | 'multi-cloud';
export type ExposureLevel = 'private' | 'internal' | 'public';
export type DiffType = 'added' | 'removed' | 'modified';
export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type UserRole = 'viewer' | 'operator' | 'admin';
export type LLMProvider = 'openai-compatible' | 'anthropic' | 'gemini' | 'ollama';
export type AdvisoryStatus = 'completed' | 'offline_fallback' | 'provider_error';

export interface CanonicalAsset {
  resource_id: string; resource_name: string; resource_type: string; cloud_provider: CloudProvider;
  region: string; account_id: string; owner: string | null; exposure_level: ExposureLevel;
  network_config: Record<string, unknown>; iam_config: Record<string, unknown>;
  tags: Record<string, string>; raw_metadata: Record<string, unknown>;
}

export interface SnapshotSummary {
  id: string; name: string; cloud_provider: string; source_type: string;
  asset_count: number; description: string | null; created_by: string; created_at: string;
}

export interface SnapshotDetail extends SnapshotSummary {
  assets: CanonicalAsset[];
}

export interface FieldDelta { field: string; old_value: unknown; new_value: unknown; }

export interface DiffItem {
  diff_type: DiffType; resource_id: string; resource_name: string; resource_type: string;
  cloud_provider: string; owner: string | null; exposure_level: string;
  deltas: FieldDelta[]; exposure_escalated: boolean; iam_escalated: boolean; owner_drifted: boolean;
}

export interface OwnerGroup {
  owner: string; asset_count: number; exposure_escalated_count: number; resource_ids: string[];
}

export interface DiffResponse {
  id: string; base_snapshot_id: string; target_snapshot_id: string;
  added_count: number; removed_count: number; modified_count: number;
  items: DiffItem[]; exposure_summary: Record<string, number>;
  owner_grouping: OwnerGroup[]; created_by: string; created_at: string;
}

export interface DiffSummary {
  id: string; base_snapshot_id: string; target_snapshot_id: string;
  added_count: number; removed_count: number; modified_count: number;
  created_by: string; created_at: string;
}

export interface MLFeatureVector {
  exposure_escalation: number; iam_admin_escalation: number; unowned_resource: number;
  public_port_count: number; critical_port_open: number; storage_public_read: number;
  provider_weight: number; resource_type_weight: number;
}

export interface MLItemEvaluation {
  resource_id: string; resource_name: string; resource_type: string; cloud_provider: string;
  predicted_severity: SeverityLevel; confidence: number; anomaly_score: number;
  features: MLFeatureVector; rationale: string;
}

export interface MLEvaluationResponse {
  id: string; diff_id: string; total_evaluated: number;
  high_risk_count: number; critical_risk_count: number; anomaly_count: number;
  distribution: Record<SeverityLevel, number>; evaluations: MLItemEvaluation[];
  benchmark_metrics: Record<string, number>; created_by: string; created_at: string;
}

export interface MLBenchmarkResult {
  dataset_size: number;
  model_metrics: {
    accuracy: number; macro_f1: number; weighted_f1: number; macro_precision: number;
    macro_recall: number; total_samples: number;
    confusion_matrix: Record<string, Record<string, number>>;
    per_class: Record<string, Record<string, number>>;
  };
  baseline_metrics: { accuracy: number; macro_f1: number; };
  improvements: { accuracy_delta: number; f1_delta: number; };
  failure_cases: string[]; data_provenance: string; evaluation_command: string;
}

export interface RemediateAction {
  resource_id: string; cloud_provider: string; severity: string;
  action_type: string; recommendation: string; cli_command_example: string;
}

export interface LLMAdvisoryResponse {
  diff_id: string; provider: string; model: string; advisory_summary: string;
  prioritized_remediations: RemediateAction[]; grounded_resource_count: number;
  grounding_verified: boolean; status: AdvisoryStatus; error_message: string | null;
}

export interface AuditLogEntry {
  id: string; actor: string; role: string; action: string;
  resource_type: string; resource_id: string | null;
  details: Record<string, unknown>; created_at: string;
}

export interface SeedResponse {
  base_snapshot_id: string; target_snapshot_id: string; message: string;
}

export interface AuthState {
  token: string | null; role: UserRole | null; username: string | null; isAuthenticated: boolean;
}

export interface DemoLoginRequest { role: UserRole; username?: string; }

export interface SnapshotCreateRequest {
  name: string; cloud_provider: CloudProvider; source_type: string;
  description?: string; assets?: CanonicalAsset[]; raw_payload?: Record<string, unknown>[];
}
