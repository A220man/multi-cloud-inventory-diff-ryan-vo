"""Tests for compliance audit bundle generation and verification."""
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone
import json

from app.models.schemas import (
    CanonicalAsset,
    DiffItem,
    FieldDelta,
    ComplianceBundleRequest,
)
from app.models.entities import (
    SnapshotRecord,
    AssetRecord,
    DiffRecord,
    EvaluationRecord,
    AuditLogRecord,
)
from app.services.compliance_bundle import (
    ComplianceBundleService,
    create_compliance_bundle,
)


@pytest.fixture
def mock_db():
    """Create a mock database session."""
    return MagicMock()


@pytest.fixture
def sample_snapshot():
    """Create a sample snapshot record."""
    snap = SnapshotRecord(
        id="snap-1",
        name="Test Snapshot",
        cloud_provider="aws",
        source_type="config-export",
        asset_count=2,
        created_by="test-user",
        created_at=datetime.now(timezone.utc),
    )
    snap.assets = [
        AssetRecord(
            id="asset-1",
            snapshot_id="snap-1",
            resource_id="i-12345",
            resource_name="web-server",
            resource_type="EC2 Instance",
            cloud_provider="aws",
            region="us-east-1",
            account_id="111222333444",
            owner="team-a",
            exposure_level="public",
            network_config_json='{"public_ip": "1.2.3.4", "admin_ports": [22]}',
            iam_config_json='{}',
            tags_json='{"Environment": "prod"}',
            raw_metadata_json='{}',
            created_at=datetime.now(timezone.utc),
        ),
        AssetRecord(
            id="asset-2",
            snapshot_id="snap-1",
            resource_id="sg-67890",
            resource_name="web-sg",
            resource_type="Security Group",
            cloud_provider="aws",
            region="us-east-1",
            account_id="111222333444",
            owner="team-a",
            exposure_level="public",
            network_config_json='{"ingress": [{"port": 80, "cidr": "0.0.0.0/0"}]}',
            iam_config_json='{}',
            tags_json='{}',
            raw_metadata_json='{}',
            created_at=datetime.now(timezone.utc),
        ),
    ]
    return snap


@pytest.fixture
def sample_diff():
    """Create a sample diff record."""
    diff = DiffRecord(
        id="diff-1",
        base_snapshot_id="snap-1",
        target_snapshot_id="snap-2",
        added_count=1,
        removed_count=0,
        modified_count=1,
        diff_payload_json=json.dumps([
            {
                "diff_type": "added",
                "resource_id": "i-new",
                "resource_name": "new-instance",
                "resource_type": "EC2 Instance",
                "cloud_provider": "aws",
                "field_deltas": [],
                "exposure_escalated": False,
                "owner_drifted": False,
            },
            {
                "diff_type": "modified",
                "resource_id": "i-12345",
                "resource_name": "web-server",
                "resource_type": "EC2 Instance",
                "cloud_provider": "aws",
                "field_deltas": [
                    {"field": "exposure_level", "old_value": "private", "new_value": "public"}
                ],
                "exposure_escalated": True,
                "owner_drifted": False,
            },
        ]),
        exposure_summary_json=json.dumps({"public": 2, "private": 0, "internal": 0}),
        owner_grouping_json=json.dumps({"team-a": ["i-12345", "i-new"]}),
        created_by="test-user",
        created_at=datetime.now(timezone.utc),
    )
    return diff


@pytest.fixture
def sample_evaluation():
    """Create a sample evaluation record."""
    return EvaluationRecord(
        id="eval-1",
        diff_id="diff-1",
        total_evaluated=2,
        high_risk_count=1,
        critical_risk_count=0,
        anomaly_count=1,
        evaluation_payload_json=json.dumps({
            "evaluations": [
                {
                    "resource_id": "i-12345",
                    "severity": "HIGH",
                    "confidence": 0.9,
                    "rationale": "Public exposure escalation detected",
                }
            ],
            "results": [
                {
                    "policy_id": "policies/public_exposure",
                    "result": [{"msg": "Resource i-12345 has public exposure"}],
                    "violations": [{"msg": "Resource i-12345 has public exposure"}],
                    "allowed": False,
                }
            ],
        }),
        created_by="test-user",
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_audit_log():
    """Create a sample audit log record."""
    return AuditLogRecord(
        id="audit-1",
        actor="test-user",
        role="operator",
        action="CREATE_SNAPSHOT",
        resource_type="snapshot",
        resource_id="snap-1",
        details_json=json.dumps({"cloud_provider": "aws"}),
        created_at=datetime.now(timezone.utc),
    )


def test_compliance_bundle_service_initialization():
    """Test ComplianceBundleService can be initialized."""
    with patch("app.services.compliance_bundle.Session") as mock_session:
        service = ComplianceBundleService(mock_session)
        assert service is not None
        assert service.private_key is not None
        assert service.public_key is not None


def test_compliance_bundle_sign_verify():
    """Test bundle signing and verification."""
    with patch("app.services.compliance_bundle.Session") as mock_session:
        service = ComplianceBundleService(mock_session)

        bundle = {
            "metadata": {"bundle_id": "test-bundle"},
            "snapshots": [],
            "diffs": [],
        }

        # Sign the bundle
        signed = service.sign_bundle(bundle, "test-user", "operator")
        assert "proof" in signed
        assert signed["proof"]["type"] == "RsaSignature2018"
        assert "jws" in signed["proof"]

        # Verify the bundle
        valid = service.verify_bundle(signed)
        assert valid is True


def test_compliance_bundle_verify_fails_on_tampering():
    """Test that verification fails when bundle is tampered with."""
    with patch("app.services.compliance_bundle.Session") as mock_session:
        service = ComplianceBundleService(mock_session)

        bundle = {
            "metadata": {"bundle_id": "test-bundle"},
            "snapshots": [],
            "diffs": [],
        }

        signed = service.sign_bundle(bundle, "test-user", "operator")

        # Tamper with the bundle
        signed["metadata"]["bundle_id"] = "tampered-bundle"

        valid = service.verify_bundle(signed)
        assert valid is False


def test_generate_bundle_collects_snapshots(mock_db, sample_snapshot):
    """Test bundle generation collects snapshot lineage."""
    mock_db.query.return_value.filter.return_value.first.return_value = sample_snapshot

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        lineage = service._collect_snapshot_lineage("snap-1")

        assert lineage.snapshot_id == "snap-1"
        assert lineage.name == "Test Snapshot"
        assert lineage.asset_count == 2
        assert len(lineage.assets) == 2
        assert lineage.assets[0]["resource_id"] == "i-12345"


def test_generate_bundle_collects_diffs(mock_db, sample_diff):
    """Test bundle generation collects diff evidence."""
    mock_db.query.return_value.filter.return_value.first.return_value = sample_diff

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        evidence = service._collect_diff_evidence("diff-1")

        assert evidence.diff_id == "diff-1"
        assert evidence.added_count == 1
        assert evidence.modified_count == 1
        assert len(evidence.diff_items) == 2
        assert evidence.diff_items[1]["exposure_escalated"] is True


def test_generate_bundle_collects_opa_violations(mock_db, sample_evaluation):
    """Test bundle generation collects OPA violations."""
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [sample_evaluation]

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        violations = service._collect_opa_violations("diff-1")

        assert len(violations) == 1
        assert violations[0].policy_id == "policies/public_exposure"
        assert len(violations[0].violations) == 1
        assert violations[0].allowed is False


def test_generate_bundle_collects_ml_evaluations(mock_db, sample_evaluation):
    """Test bundle generation collects ML evaluations."""
    mock_db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [sample_evaluation]

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        evaluations = service._collect_ml_evaluations("diff-1")

        assert len(evaluations) == 1
        assert evaluations[0].evaluation_id == "eval-1"
        assert evaluations[0].high_risk_count == 1
        assert len(evaluations[0].evaluations) == 1
        assert evaluations[0].evaluations[0]["severity"] == "HIGH"


def test_generate_bundle_collects_audit_logs(mock_db, sample_audit_log):
    """Test bundle generation collects audit logs."""
    mock_db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [sample_audit_log]

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        logs = service._collect_audit_logs(["snap-1"], ["diff-1"])

        assert len(logs) == 1
        assert logs[0]["actor"] == "test-user"
        assert logs[0]["action"] == "CREATE_SNAPSHOT"


def test_generate_full_bundle(mock_db, sample_snapshot, sample_diff, sample_evaluation, sample_audit_log):
    """Test generating a complete compliance bundle."""
    # Setup mock queries
    def query_side_effect(model):
        mock_query = MagicMock()
        if model == SnapshotRecord:
            mock_query.filter.return_value.first.return_value = sample_snapshot
        elif model == DiffRecord:
            mock_query.filter.return_value.first.return_value = sample_diff
        elif model == EvaluationRecord:
            mock_query.filter.return_value.order_by.return_value.all.return_value = [sample_evaluation]
        elif model == AuditLogRecord:
            mock_query.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [sample_audit_log]
        return mock_query

    mock_db.query.side_effect = query_side_effect

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        bundle = service.generate_bundle(
            snapshot_ids=["snap-1"],
            diff_ids=["diff-1"],
            created_by="test-user",
            description="Test compliance bundle",
        )

        assert bundle["type"] == ["VerifiableCredential", "ComplianceAuditBundle"]
        assert bundle["metadata"]["created_by"] == "test-user"
        assert len(bundle["snapshots"]) == 1
        assert len(bundle["diffs"]) == 1
        assert len(bundle["opa_violations"]) == 1
        assert len(bundle["ml_evaluations"]) == 1
        assert len(bundle["audit_logs"]) == 1
        assert "proof" in bundle


def test_export_csv_generates_all_sections(mock_db, sample_snapshot, sample_diff, sample_evaluation, sample_audit_log):
    """Test CSV export generates all expected sections."""
    def query_side_effect(model):
        mock_query = MagicMock()
        if model == SnapshotRecord:
            mock_query.filter.return_value.first.return_value = sample_snapshot
        elif model == DiffRecord:
            mock_query.filter.return_value.first.return_value = sample_diff
        elif model == EvaluationRecord:
            mock_query.filter.return_value.order_by.return_value.all.return_value = [sample_evaluation]
        elif model == AuditLogRecord:
            mock_query.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [sample_audit_log]
        return mock_query

    mock_db.query.side_effect = query_side_effect

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        service = ComplianceBundleService(mock_db)
        bundle = service.generate_bundle(
            snapshot_ids=["snap-1"],
            diff_ids=["diff-1"],
            created_by="test-user",
        )
        csv_exports = service.export_csv(bundle)

        # Check all expected CSV files are generated
        assert "snapshots.csv" in csv_exports
        assert "assets.csv" in csv_exports
        assert "diffs.csv" in csv_exports
        assert "diff_items.csv" in csv_exports
        assert "opa_violations.csv" in csv_exports
        assert "ml_evaluations.csv" in csv_exports
        assert "audit_logs.csv" in csv_exports

        # Check content has headers
        assert "snapshot_id" in csv_exports["snapshots.csv"]
        assert "resource_id" in csv_exports["assets.csv"]
        assert "diff_id" in csv_exports["diffs.csv"]
        assert "diff_type" in csv_exports["diff_items.csv"]
        assert "policy_id" in csv_exports["opa_violations.csv"]
        assert "evaluation_id" in csv_exports["ml_evaluations.csv"]
        assert "id" in csv_exports["audit_logs.csv"]


def test_create_compliance_bundle_convenience_function(
    mock_db, sample_snapshot, sample_diff, sample_evaluation, sample_audit_log
):
    """Test the convenience function creates and signs a bundle."""
    def query_side_effect(model):
        mock_query = MagicMock()
        if model == SnapshotRecord:
            mock_query.filter.return_value.first.return_value = sample_snapshot
        elif model == DiffRecord:
            mock_query.filter.return_value.first.return_value = sample_diff
        elif model == EvaluationRecord:
            mock_query.filter.return_value.order_by.return_value.all.return_value = [sample_evaluation]
        elif model == AuditLogRecord:
            mock_query.filter.return_value.order_by.return_value.limit.return_value.all.return_value = [sample_audit_log]
        return mock_query

    mock_db.query.side_effect = query_side_effect

    with patch("app.services.compliance_bundle.Session", return_value=mock_db):
        bundle = create_compliance_bundle(
            db=mock_db,
            snapshot_ids=["snap-1"],
            diff_ids=["diff-1"],
            created_by="test-user",
            description="Test bundle",
        )

        assert bundle["metadata"]["created_by"] == "test-user"
        assert bundle["metadata"]["description"] == "Test bundle"
        assert "proof" in bundle
        assert bundle["proof"]["jws"] != "unsigned-demo"


def test_compliance_bundle_request_schema():
    """Test ComplianceBundleRequest schema validation."""
    req = ComplianceBundleRequest(
        snapshot_ids=["snap-1"],
        diff_ids=["diff-1"],
        description="Test",
        include_ml=True,
        include_opa=False,
        include_audit=True,
        sign_bundle=True,
    )
    assert req.snapshot_ids == ["snap-1"]
    assert req.diff_ids == ["diff-1"]
    assert req.include_opa is False
    assert req.sign_bundle is True


def test_compliance_bundle_request_empty_lists():
    """Test ComplianceBundleRequest accepts empty lists."""
    req = ComplianceBundleRequest(snapshot_ids=[], diff_ids=[])
    assert req.snapshot_ids == []
    assert req.diff_ids == []


def test_compliance_bundle_request_validation():
    """Test ComplianceBundleRequest validation."""
    # At least one of snapshot_ids or diff_ids must be provided
    # This validation is done in the API endpoint, not the schema
    req = ComplianceBundleRequest(snapshot_ids=[], diff_ids=[])
    assert req.snapshot_ids == []
    assert req.diff_ids == []
