"""Tests for snapshot diff calculation and grouping engine."""
from app.models.schemas import CanonicalAsset
from app.services.diff_engine import DiffEngine


def test_diff_engine_detects_additions_and_removals():
    base = [
        CanonicalAsset(
            resource_id="arn:aws:s3:::old-bkt",
            resource_name="old-bkt",
            resource_type="storage.bucket",
            cloud_provider="aws",
            region="us-east-1",
            account_id="111",
            owner="infra",
            exposure_level="private",
        )
    ]
    target = [
        CanonicalAsset(
            resource_id="arn:aws:s3:::new-bkt",
            resource_name="new-bkt",
            resource_type="storage.bucket",
            cloud_provider="aws",
            region="us-east-1",
            account_id="111",
            owner="infra",
            exposure_level="public",
        )
    ]

    items, summary, grouping = DiffEngine.compute_diff(base, target)
    assert len(items) == 2
    types = {i.diff_type for i in items}
    assert types == {"added", "removed"}
    assert summary["public_added"] == 1
    assert summary["exposure_escalated"] == 1


def test_diff_engine_detects_exposure_and_owner_drift():
    base = [
        CanonicalAsset(
            resource_id="arn:aws:ec2:vm-1",
            resource_name="vm-1",
            resource_type="compute.instance",
            cloud_provider="aws",
            region="us-east-1",
            account_id="111",
            owner="alice",
            exposure_level="internal",
            network_config={"open_ports": ["80"]},
            iam_config={"has_admin_privilege": False},
        )
    ]
    target = [
        CanonicalAsset(
            resource_id="arn:aws:ec2:vm-1",
            resource_name="vm-1",
            resource_type="compute.instance",
            cloud_provider="aws",
            region="us-east-1",
            account_id="111",
            owner=None,  # Owner drifted to unassigned
            exposure_level="public",  # Exposure escalated
            network_config={"open_ports": ["80", "22"]},
            iam_config={"has_admin_privilege": True},  # Admin IAM attached
        )
    ]

    items, summary, grouping = DiffEngine.compute_diff(base, target)
    assert len(items) == 1
    item = items[0]
    assert item.diff_type == "modified"
    assert item.exposure_escalated is True
    assert item.iam_escalated is True
    assert item.owner_drifted is True

    # Check field deltas
    delta_fields = {d.field for d in item.deltas}
    assert "exposure_level" in delta_fields
    assert "owner" in delta_fields
    assert "iam_config.has_admin_privilege" in delta_fields

    # Check grouping
    assert len(grouping) == 1
    assert grouping[0].owner == "unassigned"
    assert grouping[0].exposure_escalated_count == 1
