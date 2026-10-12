"""FastAPI API endpoints for multi-cloud inventory management, diffing, ML, and advisory."""
from datetime import datetime, timezone
import json
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.auth import AuthUser, create_demo_token, require_role
from app.core.config import settings
from app.core.database import get_db
from app.ml.classifier import DriftRiskClassifier
from app.ml.evaluate import run_benchmark
from app.models.entities import AssetRecord, DiffRecord, EvaluationRecord, SnapshotRecord
from app.models.schemas import (
    AuditLogEntry,
    CanonicalAsset,
    DemoTokenRequest,
    DemoTokenResponse,
    DiffItem,
    DiffRequest,
    DiffResponse,
    DiffSummary,
    LLMAdvisoryRequest,
    LLMAdvisoryResponse,
    MLEvaluationRequest,
    MLEvaluationResponse,
    OwnerGroup,
    SnapshotCreate,
    SnapshotDetail,
    SnapshotSummary,
)
from app.services.audit import AuditService
from app.services.diff_engine import DiffEngine
from app.services.llm_advisor import generate_advisory
from app.services.normalizer import MultiCloudNormalizer

api_router = APIRouter()


def _snap_summary(s: SnapshotRecord) -> SnapshotSummary:
    return SnapshotSummary(
        id=s.id, name=s.name, cloud_provider=s.cloud_provider, source_type=s.source_type,
        asset_count=s.asset_count, description=s.description, created_by=s.created_by, created_at=s.created_at,
    )


def _persist_assets(db: Session, snap_id: str, assets: list[CanonicalAsset]):
    now = datetime.now(timezone.utc)
    for a in assets:
        db.add(AssetRecord(
            id=str(uuid.uuid4()), snapshot_id=snap_id, resource_id=a.resource_id,
            resource_name=a.resource_name, resource_type=a.resource_type, cloud_provider=a.cloud_provider,
            region=a.region, account_id=a.account_id, owner=a.owner, exposure_level=a.exposure_level,
            network_config_json=json.dumps(a.network_config), iam_config_json=json.dumps(a.iam_config),
            tags_json=json.dumps(a.tags), raw_metadata_json=json.dumps(a.raw_metadata), created_at=now,
        ))


def _diff_to_response(diff: DiffRecord) -> DiffResponse:
    return DiffResponse(
        id=diff.id, base_snapshot_id=diff.base_snapshot_id, target_snapshot_id=diff.target_snapshot_id,
        added_count=diff.added_count, removed_count=diff.removed_count, modified_count=diff.modified_count,
        items=[DiffItem(**i) for i in json.loads(diff.diff_payload_json)],
        exposure_summary=json.loads(diff.exposure_summary_json),
        owner_grouping=[OwnerGroup(**og) for og in json.loads(diff.owner_grouping_json)],
        created_by=diff.created_by, created_at=diff.created_at,
    )


def _asset(rid, name, rtype, cloud, region, acct, owner, exp, pub_ip=None, ports=None, admin=False, tags=None):
    return CanonicalAsset(
        resource_id=rid, resource_name=name, resource_type=rtype, cloud_provider=cloud,
        region=region, account_id=acct, owner=owner, exposure_level=exp,
        network_config={"public_ip": pub_ip, "open_ports": ports or []},
        iam_config={"has_admin_privilege": admin}, tags=tags or {},
    )


@api_router.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": settings.ENVIRONMENT,
        "demo_mode": settings.DEMO_MODE,
        "version": "1.0.0",
        "llm_provider": settings.LLM_PROVIDER,
        "llm_model": settings.LLM_MODEL,
    }


@api_router.post("/auth/demo-token", response_model=DemoTokenResponse)
def request_demo_token(payload: DemoTokenRequest):
    if not settings.DEMO_MODE:
        raise HTTPException(status_code=403, detail="Demo token endpoint disabled. Production requires Keycloak OIDC.")
    token = create_demo_token(username=payload.username or "demo-user", role=payload.role)
    return DemoTokenResponse(access_token=token, role=payload.role, username=payload.username or "demo-user", expires_in=28800)


@api_router.post("/snapshots", response_model=SnapshotSummary, status_code=status.HTTP_201_CREATED)
def create_snapshot(
    payload: SnapshotCreate,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("operator")),
):
    snapshot_id = str(uuid.uuid4())
    assets_to_save: list[CanonicalAsset] = []
    if payload.raw_payload:
        for raw in payload.raw_payload:
            norm = MultiCloudNormalizer.normalize_asset(raw, default_provider=payload.cloud_provider)
            assets_to_save.append(norm)
    else:
        assets_to_save.extend(payload.assets)

    snap = SnapshotRecord(
        id=snapshot_id, name=payload.name, cloud_provider=payload.cloud_provider,
        source_type=payload.source_type, asset_count=len(assets_to_save),
        description=payload.description, created_by=user.username, created_at=datetime.now(timezone.utc),
    )
    db.add(snap)
    _persist_assets(db, snapshot_id, assets_to_save)
    db.commit()
    db.refresh(snap)

    AuditService.record_event(
        db=db, actor=user.username, role=user.roles[0] if user.roles else "operator",
        action="CREATE_SNAPSHOT", resource_type="snapshot", resource_id=snapshot_id,
        details={"name": snap.name, "provider": snap.cloud_provider, "asset_count": snap.asset_count},
    )
    return _snap_summary(snap)


@api_router.get("/snapshots", response_model=list[SnapshotSummary])
def list_snapshots(
    provider: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("viewer")),
):
    q = db.query(SnapshotRecord)
    if provider:
        q = q.filter(SnapshotRecord.cloud_provider == provider)
    return [_snap_summary(s) for s in q.order_by(SnapshotRecord.created_at.desc()).offset(offset).limit(limit).all()]


@api_router.get("/snapshots/{snapshot_id}", response_model=SnapshotDetail)
def get_snapshot(
    snapshot_id: str,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("viewer")),
):
    snap = db.query(SnapshotRecord).filter(SnapshotRecord.id == snapshot_id).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return SnapshotDetail(
        **_snap_summary(snap).model_dump(),
        assets=[CanonicalAsset.from_record(a) for a in snap.assets],
    )


@api_router.delete("/snapshots/{snapshot_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_snapshot(
    snapshot_id: str, db: Session = Depends(get_db), user: AuthUser = Depends(require_role("admin")),
):
    snap = db.query(SnapshotRecord).filter(SnapshotRecord.id == snapshot_id).first()
    if not snap:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    name = snap.name
    db.delete(snap)
    db.commit()
    AuditService.record_event(
        db=db, actor=user.username, role=user.roles[0] if user.roles else "admin",
        action="DELETE_SNAPSHOT", resource_type="snapshot", resource_id=snapshot_id, details={"name": name},
    )


@api_router.post("/snapshots/sample-seed", status_code=status.HTTP_201_CREATED)
def seed_sample_snapshots(
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("operator")),
):
    a = "111222333444"
    s3_arn = "arn:aws:s3:::prod-customer-data-lake"
    ec2_arn = f"arn:aws:ec2:us-east-1:{a}:instance/i-0a1b2c3d4e5f6g7h8"
    rds_arn = f"arn:aws:rds:us-east-1:{a}:db:rds-billing-db"
    k8s = _asset("//compute.googleapis.com/projects/fintech-prod/zones/us-central1-a/instances/k8s-master-01", "k8s-master-01", "compute.instance", "gcp", "us-central1", "fintech-prod", "platform-team", "internal", tags={"owner": "platform-team"})
    az_vm = _asset("/subscriptions/sub-az-1/resourceGroups/prod-rg/providers/Microsoft.Compute/virtualMachines/vm-payment-gw", "vm-payment-gw", "compute.instance", "azure", "eastus", "sub-az-1", "fintech-core", "private")
    base_assets = [
        _asset(s3_arn, "prod-customer-data-lake", "storage.bucket", "aws", "us-east-1", a, "sec-team", "private", tags={"Owner": "sec-team", "Environment": "production"}),
        _asset(ec2_arn, "bastion-host-01", "compute.instance", "aws", "us-east-1", a, "infra-ops", "internal", ports=["10.0.0.0/8:22"], tags={"Owner": "infra-ops"}),
        k8s, az_vm,
        _asset(rds_arn, "rds-billing-db", "database.relational", "aws", "us-east-1", a, "finance-team", "public", pub_ip="54.210.40.11", ports=["0.0.0.0/0:5432"], tags={"Owner": "finance-team"}),
    ]
    target_assets = [
        _asset(s3_arn, "prod-customer-data-lake", "storage.bucket", "aws", "us-east-1", a, "sec-team", "public", pub_ip="54.210.12.33", ports=["0.0.0.0/0:443"], tags={"Owner": "sec-team", "Environment": "production"}),
        _asset(ec2_arn, "bastion-host-01", "compute.instance", "aws", "us-east-1", a, "infra-ops", "public", pub_ip="54.210.40.11", ports=["0.0.0.0/0:22"], admin=True, tags={"Owner": "infra-ops"}),
        k8s, az_vm,
        _asset(rds_arn, "rds-billing-db", "database.relational", "aws", "us-east-1", a, None, "public", pub_ip="54.210.40.11", ports=["0.0.0.0/0:5432"]),
        _asset("arn:aws:s3:::untracked-exfil-staging", "untracked-exfil-staging", "storage.bucket", "aws", "us-east-1", a, None, "public", pub_ip="54.210.99.11", ports=["0.0.0.0/0:443"]),
    ]

    base_id, target_id = str(uuid.uuid4()), str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    base_snap = SnapshotRecord(id=base_id, name="Baseline Production Inventory (Q3)", cloud_provider="multi-cloud", source_type="automated-sync", asset_count=len(base_assets), description="Baseline configuration", created_by="system-seed", created_at=now)
    target_snap = SnapshotRecord(id=target_id, name="Drifted Production Audit (Today)", cloud_provider="multi-cloud", source_type="audit-scan", asset_count=len(target_assets), description="Drifted scan", created_by="system-seed", created_at=now)
    db.add(base_snap)
    db.add(target_snap)
    _persist_assets(db, base_id, base_assets)
    _persist_assets(db, target_id, target_assets)
    db.commit()

    AuditService.record_event(
        db=db,
        actor=user.username,
        role=user.roles[0] if user.roles else "operator",
        action="SEED_SAMPLE_SNAPSHOTS",
        resource_type="snapshot",
        resource_id=target_id,
        details={"base_snapshot_id": base_id, "target_snapshot_id": target_id},
    )
    return {"message": "Sample snapshots seeded successfully", "base_snapshot_id": base_id, "target_snapshot_id": target_id}


@api_router.post("/diffs", response_model=DiffResponse, status_code=status.HTTP_201_CREATED)
def calculate_diff(
    payload: DiffRequest,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("operator")),
):
    base_snap = db.query(SnapshotRecord).filter(SnapshotRecord.id == payload.base_snapshot_id).first()
    target_snap = db.query(SnapshotRecord).filter(SnapshotRecord.id == payload.target_snapshot_id).first()
    if not base_snap or not target_snap:
        raise HTTPException(status_code=404, detail="One or both snapshots not found")

    base_assets = [CanonicalAsset.from_record(a) for a in base_snap.assets]
    target_assets = [CanonicalAsset.from_record(a) for a in target_snap.assets]
    diff_items, exposure_summary, owner_grouping = DiffEngine.compute_diff(base_assets, target_assets)

    diff_id = str(uuid.uuid4())
    diff_rec = DiffRecord(
        id=diff_id, base_snapshot_id=payload.base_snapshot_id, target_snapshot_id=payload.target_snapshot_id,
        added_count=sum(1 for i in diff_items if i.diff_type == "added"),
        removed_count=sum(1 for i in diff_items if i.diff_type == "removed"),
        modified_count=sum(1 for i in diff_items if i.diff_type == "modified"),
        diff_payload_json=json.dumps([i.model_dump() for i in diff_items]),
        exposure_summary_json=json.dumps(exposure_summary),
        owner_grouping_json=json.dumps([og.model_dump() for og in owner_grouping]),
        created_by=user.username, created_at=datetime.now(timezone.utc),
    )
    db.add(diff_rec)
    db.commit()

    AuditService.record_event(
        db=db, actor=user.username, role=user.roles[0] if user.roles else "operator",
        action="COMPUTE_DIFF", resource_type="diff", resource_id=diff_id,
        details={"base_snapshot_id": payload.base_snapshot_id, "target_snapshot_id": payload.target_snapshot_id, "total_changes": len(diff_items)},
    )
    return _diff_to_response(diff_rec)


@api_router.get("/diffs", response_model=list[DiffSummary])
def list_diffs(
    snapshot_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("viewer")),
):
    q = db.query(DiffRecord)
    if snapshot_id:
        q = q.filter((DiffRecord.base_snapshot_id == snapshot_id) | (DiffRecord.target_snapshot_id == snapshot_id))
    return [
        DiffSummary(
            id=d.id, base_snapshot_id=d.base_snapshot_id, target_snapshot_id=d.target_snapshot_id,
            added_count=d.added_count, removed_count=d.removed_count, modified_count=d.modified_count,
            created_by=d.created_by, created_at=d.created_at,
        )
        for d in q.order_by(DiffRecord.created_at.desc()).offset(offset).limit(limit).all()
    ]


@api_router.get("/diffs/{diff_id}", response_model=DiffResponse)
def get_diff(
    diff_id: str,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("viewer")),
):
    diff = db.query(DiffRecord).filter(DiffRecord.id == diff_id).first()
    if not diff:
        raise HTTPException(status_code=404, detail="Diff not found")
    return _diff_to_response(diff)


@api_router.post("/ml/evaluate", response_model=MLEvaluationResponse)
def evaluate_diff_ml(
    payload: MLEvaluationRequest,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("operator")),
):
    diff = db.query(DiffRecord).filter(DiffRecord.id == payload.diff_id).first()
    if not diff:
        raise HTTPException(status_code=404, detail="Diff not found")

    items = [DiffItem(**i) for i in json.loads(diff.diff_payload_json)]
    evaluations = DriftRiskClassifier.batch_classify(items)

    crit = sum(1 for e in evaluations if e.predicted_severity == "CRITICAL")
    high = sum(1 for e in evaluations if e.predicted_severity == "HIGH")
    bench = run_benchmark()["model_metrics"]

    eval_id = str(uuid.uuid4())
    eval_rec = EvaluationRecord(
        id=eval_id, diff_id=diff.id, total_evaluated=len(evaluations),
        high_risk_count=high, critical_risk_count=crit,
        anomaly_count=sum(1 for e in evaluations if e.anomaly_score >= payload.anomaly_threshold),
        evaluation_payload_json=json.dumps([e.model_dump() for e in evaluations]),
        created_by=user.username, created_at=datetime.now(timezone.utc),
    )
    db.add(eval_rec)
    db.commit()

    AuditService.record_event(
        db=db, actor=user.username, role=user.roles[0] if user.roles else "operator",
        action="RUN_ML_EVALUATION", resource_type="ml_evaluation", resource_id=eval_id,
        details={"diff_id": diff.id, "total": len(evaluations), "critical": crit},
    )

    return MLEvaluationResponse(
        id=eval_id, diff_id=diff.id, total_evaluated=len(evaluations),
        high_risk_count=high, critical_risk_count=crit, anomaly_count=eval_rec.anomaly_count,
        distribution={
            "CRITICAL": crit, "HIGH": high,
            "MEDIUM": sum(1 for e in evaluations if e.predicted_severity == "MEDIUM"),
            "LOW": sum(1 for e in evaluations if e.predicted_severity == "LOW"),
        },
        evaluations=evaluations,
        benchmark_metrics={"accuracy": bench["accuracy"], "macro_f1": bench["macro_f1"]},
        created_by=user.username, created_at=eval_rec.created_at,
    )


@api_router.get("/ml/benchmark")
def get_ml_benchmark(user: AuthUser = Depends(require_role("viewer"))):
    bench = run_benchmark()
    m, b = bench["model_metrics"], bench["baseline_metrics"]
    return {
        "dataset_size": m["total_samples"], "model_metrics": m, "baseline_metrics": b,
        "improvements": {
            "accuracy_delta": round(m["accuracy"] - b["accuracy"], 4),
            "f1_delta": round(m["macro_f1"] - b["macro_f1"], 4),
        },
        "failure_cases": [f"[{f['id']}] {f['resource_name']}: Truth={f['ground_truth']}, Pred={f['predicted']}" for f in bench.get("failures", [])],
        "data_provenance": "Curated ground-truth multi-cloud drift incidents across AWS Config, GCP CAI, and Azure Resource Graph",
        "evaluation_command": "PYTHONPATH=backend python3 -m app.ml.evaluate",
    }


@api_router.post("/advisory/generate", response_model=LLMAdvisoryResponse)
def generate_llm_advisory(
    payload: LLMAdvisoryRequest, db: Session = Depends(get_db), user: AuthUser = Depends(require_role("operator")),
):
    diff = db.query(DiffRecord).filter(DiffRecord.id == payload.diff_id).first()
    if not diff:
        raise HTTPException(status_code=404, detail="Diff not found")

    items = [DiffItem(**i) for i in json.loads(diff.diff_payload_json)]
    evaluations = DriftRiskClassifier.batch_classify(items)

    advisory_resp = generate_advisory(
        diff_id=payload.diff_id, diff_items=[i.model_dump() for i in items],
        ml_evaluations=[e.model_dump() for e in evaluations],
        provider_override=payload.provider, model_override=payload.model,
    )

    AuditService.record_event(
        db=db, actor=user.username, role=user.roles[0] if user.roles else "operator",
        action="GENERATE_ADVISORY", resource_type="advisory", resource_id=payload.diff_id,
        details={"provider": payload.provider, "remediations": len(advisory_resp.prioritized_remediations)},
    )

    return LLMAdvisoryResponse(
        diff_id=advisory_resp.diff_id,
        provider=advisory_resp.provider.value if hasattr(advisory_resp.provider, "value") else str(advisory_resp.provider),
        model=advisory_resp.model or "offline-deterministic",
        advisory_summary=advisory_resp.advisory_summary,
        prioritized_remediations=advisory_resp.prioritized_remediations,
        grounded_resource_count=advisory_resp.grounded_resource_count,
        grounding_verified=advisory_resp.grounding_verified,
        status=advisory_resp.status, error_message=advisory_resp.error_message,
    )


@api_router.get("/audit", response_model=list[AuditLogEntry])
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    action: Optional[str] = None,
    resource_type: Optional[str] = None,
    db: Session = Depends(get_db),
    user: AuthUser = Depends(require_role("viewer")),
):
    return AuditService.get_events(db=db, limit=limit, offset=offset, action=action, resource_type=resource_type)