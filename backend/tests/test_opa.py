"""Tests for OPA policy management and evaluation."""
import pytest
from unittest.mock import Mock, patch, MagicMock

from app.services.opa_service import OPAService, DEFAULT_POLICIES, load_default_policies
from app.models.schemas import CanonicalAsset, DiffItem, FieldDelta


@pytest.fixture
def mock_opa_client():
    """Mock OPA client for testing."""
    with patch("app.services.opa_service.OPAClient") as mock_client:
        yield mock_client


@pytest.fixture
def opa_service(mock_opa_client):
    """Create OPAService with mocked client."""
    return OPAService()


@pytest.fixture
def sample_assets():
    """Sample canonical assets for testing."""
    return [
        CanonicalAsset(
            resource_id="arn:aws:s3:::public-bucket",
            resource_name="public-bucket",
            resource_type="aws.s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
            account_id="123456789012",
            owner="sec-team",
            exposure_level="public",
            network_config={"public_access_block": False},
            iam_config={},
            tags={"Owner": "sec-team"},
        ),
        CanonicalAsset(
            resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            resource_name="private-ec2",
            resource_type="aws.ec2_instance",
            cloud_provider="aws",
            region="us-east-1",
            account_id="123456789012",
            owner="infra-team",
            exposure_level="private",
            network_config={},
            iam_config={},
            tags={"Owner": "infra-team"},
        ),
        CanonicalAsset(
            resource_id="arn:aws:s3:::unencrypted-bucket",
            resource_name="unencrypted-bucket",
            resource_type="aws.s3_bucket",
            cloud_provider="aws",
            region="us-east-1",
            account_id="123456789012",
            owner=None,
            exposure_level="private",
            network_config={"encryption": {"enabled": False}},
            iam_config={},
            tags={},
        ),
    ]


@pytest.fixture
def sample_diff_items():
    """Sample diff items for testing."""
    return [
        DiffItem(
            diff_type="added",
            resource_id="arn:aws:s3:::new-bucket",
            resource_name="new-bucket",
            resource_type="aws.s3_bucket",
            cloud_provider="aws",
            owner="",
            exposure_level="public",
            deltas=[],
            exposure_escalated=False,
            iam_escalated=False,
            owner_drifted=False,
        ),
        DiffItem(
            diff_type="modified",
            resource_id="arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
            resource_name="modified-ec2",
            resource_type="aws.ec2_instance",
            cloud_provider="aws",
            owner="infra-team",
            exposure_level="public",
            deltas=[FieldDelta(field="exposure_level", old_value="private", new_value="public")],
            exposure_escalated=True,
            iam_escalated=False,
            owner_drifted=False,
        ),
    ]


def test_opa_service_check_connection(opa_service, mock_opa_client):
    """Test OPA connection check."""
    mock_opa_client.return_value.check_connection.return_value = True
    assert opa_service.check_connection() is True

    mock_opa_client.return_value.check_connection.return_value = False
    assert opa_service.check_connection() is False


def test_opa_service_load_policy(opa_service, mock_opa_client):
    """Test loading a policy into OPA."""
    mock_opa_client.return_value.update_policy_from_string.return_value = None
    result = opa_service.load_policy("test_policy", 'package policies.test\ndefault violation = []')
    assert result is True


def test_opa_service_load_policy_failure(opa_service, mock_opa_client):
    """Test policy load failure handling."""
    mock_opa_client.return_value.update_policy_from_string.side_effect = Exception("Connection refused")
    result = opa_service.load_policy("test_policy", 'package policies.test\ndefault violation = []')
    assert result is False


def test_opa_service_delete_policy(opa_service, mock_opa_client):
    """Test deleting a policy from OPA."""
    mock_opa_client.return_value.delete_policy.return_value = None
    result = opa_service.delete_policy("test_policy")
    assert result is True


def test_opa_service_list_policies(opa_service, mock_opa_client):
    """Test listing policies."""
    mock_opa_client.return_value.policies_list.return_value = [
        "policies/public_exposure",
        "policies/unowned_resources",
        "system/kubernetes",
    ]
    policies = opa_service.list_policies()
    assert "policies/public_exposure" in policies
    assert "policies/unowned_resources" in policies
    assert "system/kubernetes" not in policies  # filtered out


def test_opa_service_evaluate_policy(opa_service, mock_opa_client):
    """Test evaluating a single policy."""
    mock_opa_client.return_value.check_policy.return_value = {
        "result": ["violation 1", "violation 2"]
    }
    result = opa_service.evaluate_policy("test_policy", {"assets": []})
    assert result["policy_id"] == "test_policy"
    assert len(result["violations"]) == 2
    assert result["allowed"] is False


def test_opa_service_evaluate_policy_allowed(opa_service, mock_opa_client):
    """Test policy evaluation with no violations."""
    mock_opa_client.return_value.check_policy.return_value = {"result": []}
    result = opa_service.evaluate_policy("test_policy", {"assets": []})
    assert result["allowed"] is True


def test_opa_service_evaluate_policy_error(opa_service, mock_opa_client):
    """Test policy evaluation error handling."""
    mock_opa_client.return_value.check_policy.side_effect = Exception("OPA error")
    result = opa_service.evaluate_policy("test_policy", {"assets": []})
    assert result["allowed"] is True
    assert "error" in result


def test_opa_service_evaluate_all_policies(opa_service, mock_opa_client):
    """Test evaluating all policies."""
    mock_opa_client.return_value.policies_list.return_value = ["policies/p1", "policies/p2"]
    mock_opa_client.return_value.check_policy.return_value = {"result": ["violation"]}

    results = opa_service.evaluate_all_policies({"assets": []})
    assert len(results) == 2
    assert all(r["policy_id"] in ["policies/p1", "policies/p2"] for r in results)


def test_canonical_asset_to_opa_input(opa_service, sample_assets):
    """Test converting canonical assets to OPA input format."""
    input_data = OPAService.canonical_asset_to_opa_input([a.model_dump() for a in sample_assets])
    assert "assets" in input_data
    assert len(input_data["assets"]) == 3


def test_diff_item_to_opa_input(opa_service, sample_diff_items):
    """Test converting diff items to OPA input format."""
    input_data = OPAService.diff_item_to_opa_input([d.model_dump() for d in sample_diff_items])
    assert "diffs" in input_data
    assert len(input_data["diffs"]) == 2


def test_default_policies_exist():
    """Test that default policies are defined."""
    assert "public_exposure" in DEFAULT_POLICIES
    assert "unowned_resources" in DEFAULT_POLICIES
    assert "overly_permissive_iam" in DEFAULT_POLICIES
    assert "unencrypted_storage" in DEFAULT_POLICIES
    assert "public_s3_bucket" in DEFAULT_POLICIES
    assert "security_group_open_to_world" in DEFAULT_POLICIES
    assert "diff_exposure_escalation" in DEFAULT_POLICIES
    assert "diff_unowned_new_resource" in DEFAULT_POLICIES

    # Verify each policy has valid Rego syntax (basic check)
    for policy_id, rego in DEFAULT_POLICIES.items():
        assert "package policies." in rego
        assert "default violation = []" in rego
        assert "violation[msg]" in rego


def test_load_default_policies(opa_service, mock_opa_client):
    """Test loading all default policies."""
    mock_opa_client.return_value.update_policy_from_string.return_value = None
    results = load_default_policies(opa_service)
    assert len(results) == len(DEFAULT_POLICIES)
    assert all(results.values())


def test_opa_service_initialization():
    """Test OPAService can be initialized with custom host/port."""
    with patch("app.services.opa_service.OPAClient") as mock_client:
        service = OPAService(host="opa.example.com", port=9191)
        mock_client.assert_called_once_with(host="opa.example.com", port=9191, version="v1")
