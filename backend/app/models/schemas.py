"""Pydantic schemas for multi-cloud inventory requests and responses."""
from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field


class CanonicalAsset(BaseModel):
    resource_id: str = Field(..., description="Unique cross-cloud resource identifier (ARN, URN, or Resource ID)")
    resource_name: str = Field(..., description="Human-readable resource name")
    resource_type: str = Field(..., description="Standardized resource type (e.g. compute.instance, storage.bucket, iam.role)")
    cloud_provider: Literal["aws", "gcp", "azure"] = Field(..., description="Cloud provider")
    region: str = Field(default="global", description="Deployment region or location")
    account_id: str = Field(..., description="Account, Project, or Subscription identifier")
    owner: Optional[str] = Field(default=None, description="Assigned owner or team tag")
    exposure_level: Literal["private", "internal", "public"] = Field(default="private", description="Network exposure level")
    network_config: dict[str, Any] = Field(default_factory=dict, description="CIDRs, security groups, public IPs, open ports")
    iam_config: dict[str, Any] = Field(default_factory=dict, description="Attached policies, admin privileges, service principals")
    tags: dict[str, str] = Field(default_factory=dict, description="Resource tags / labels")
    raw_metadata: dict[str, Any] = Field(default_factory=dict, description="Raw provider export properties")

    @classmethod
    def from_record(cls, a: Any) -> "CanonicalAsset":
        return cls(
            resource_id=a.resource_id,
            resource_name=a.resource_name,
            resource_type=a.resource_type,
            cloud_provider=a.cloud_provider,
            region=a.region,
            account_id=a.account_id,
            owner=a.owner,
            exposure_level=a.exposure_level,
            network_config=a.get_network_config(),
            iam_config=a.get_iam_config(),
            tags=a.get_tags(),
            raw_metadata=a.get_raw_metadata(),
        )


class SnapshotCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    cloud_provider: Literal["aws", "gcp", "azure", "multi-cloud"] = Field(...)
    source_type: str = Field(default="export-json", max_length=64)
    description: Optional[str] = Field(default=None, max_length=255)
    assets: list[CanonicalAsset] = Field(default_factory=list)
    raw_payload: Optional[list[dict[str, Any]]] = Field(default=None, description="Optional raw provider export array")


class SnapshotSummary(BaseModel):
    id: str
    name: str
    cloud_provider: str
    source_type: str
    asset_count: int
    description: Optional[str]
    created_by: str
    created_at: datetime


class SnapshotDetail(SnapshotSummary):
    assets: list[CanonicalAsset]


class FieldDelta(BaseModel):
    field: str
    old_value: Any
    new_value: Any


class DiffItem(BaseModel):
    diff_type: Literal["added", "removed", "modified"]
    resource_id: str
    resource_name: str
    resource_type: str
    cloud_provider: str
    owner: Optional[str] = None
    exposure_level: str
    deltas: list[FieldDelta] = Field(default_factory=list)
    exposure_escalated: bool = False
    iam_escalated: bool = False
    owner_drifted: bool = False


class OwnerGroup(BaseModel):
    owner: str
    asset_count: int
    exposure_escalated_count: int
    resource_ids: list[str]


class DiffRequest(BaseModel):
    base_snapshot_id: str
    target_snapshot_id: str


class DiffResponse(BaseModel):
    id: str
    base_snapshot_id: str
    target_snapshot_id: str
    added_count: int
    removed_count: int
    modified_count: int
    items: list[DiffItem]
    exposure_summary: dict[str, int]
    owner_grouping: list[OwnerGroup]
    created_by: str
    created_at: datetime


class MLFeatureVector(BaseModel):
    exposure_escalation: int
    iam_admin_escalation: int
    unowned_resource: int
    public_port_count: int
    critical_port_open: int
    storage_public_read: int
    provider_weight: float
    resource_type_weight: float


class MLItemEvaluation(BaseModel):
    resource_id: str
    resource_name: str
    resource_type: str
    cloud_provider: str
    predicted_severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    confidence: float
    anomaly_score: float
    features: MLFeatureVector
    rationale: str


class MLEvaluationRequest(BaseModel):
    diff_id: str
    anomaly_threshold: float = Field(default=0.7, ge=0.0, le=1.0)


class MLEvaluationResponse(BaseModel):
    id: str
    diff_id: str
    total_evaluated: int
    high_risk_count: int
    critical_risk_count: int
    anomaly_count: int
    distribution: dict[str, int]
    evaluations: list[MLItemEvaluation]
    benchmark_metrics: dict[str, float]
    created_by: str
    created_at: datetime


class LLMAdvisoryRequest(BaseModel):
    diff_id: str
    provider: Optional[Literal["openai-compatible", "anthropic", "gemini", "ollama"]] = None
    model: Optional[str] = None
    focus: Optional[Literal["exposure", "iam", "compliance", "all"]] = "all"


class RemediateAction(BaseModel):
    resource_id: str
    cloud_provider: str
    severity: str
    action_type: str
    recommendation: str
    cli_command_example: str


class LLMAdvisoryResponse(BaseModel):
    diff_id: str
    provider: str
    model: str
    advisory_summary: str
    prioritized_remediations: list[RemediateAction]
    grounded_resource_count: int
    grounding_verified: bool
    status: Literal["completed", "offline_fallback", "provider_error"]
    error_message: Optional[str] = None


class AuditLogEntry(BaseModel):
    id: str
    actor: str
    role: str
    action: str
    resource_type: str
    resource_id: Optional[str]
    details: dict[str, Any]
    created_at: datetime


class DemoTokenRequest(BaseModel):
    role: Literal["viewer", "operator", "admin"] = "operator"
    username: Optional[str] = "demo-user"


class DemoTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    role: str
    username: str
    expires_in: int
