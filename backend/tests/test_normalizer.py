"""Tests for multi-cloud asset export normalization."""
from app.services.normalizer import MultiCloudNormalizer


def test_normalize_aws_ec2_with_public_sg():
    raw_ec2 = {
        "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc1234",
        "resourceName": "web-server-01",
        "resourceType": "AWS::EC2::Instance",
        "awsRegion": "us-east-1",
        "accountId": "123456789012",
        "tags": [{"Key": "Owner", "Value": "frontend-team"}],
        "configuration": {
            "publicIpAddress": "54.200.10.1",
            "ipPermissions": [
                {"IpRanges": [{"CidrIp": "0.0.0.0/0"}], "FromPort": 80, "ToPort": 80}
            ],
        },
    }
    asset = MultiCloudNormalizer.normalize_asset(raw_ec2, "aws")
    assert asset.cloud_provider == "aws"
    assert asset.resource_name == "web-server-01"
    assert asset.resource_type == "compute.instance"
    assert asset.owner == "frontend-team"
    assert asset.exposure_level == "public"
    assert "80" in asset.network_config["open_ports"]


def test_normalize_gcp_cloud_asset_inventory():
    raw_gcp = {
        "name": "//compute.googleapis.com/projects/my-prod/zones/us-central1-a/instances/worker-vm",
        "assetType": "compute.googleapis.com/Instance",
        "location": "us-central1-a",
        "project": "my-prod",
        "resource": {
            "data": {
                "name": "worker-vm",
                "labels": {"owner": "data-eng"},
                "networkInterfaces": [
                    {"accessConfigs": [{"natIP": "35.190.20.10"}]}
                ],
            }
        },
    }
    asset = MultiCloudNormalizer.normalize_asset(raw_gcp, "gcp")
    assert asset.cloud_provider == "gcp"
    assert asset.resource_name == "worker-vm"
    assert asset.resource_type == "compute.instance"
    assert asset.owner == "data-eng"
    assert asset.exposure_level == "public"
    assert asset.network_config["public_ip"] == "35.190.20.10"


def test_normalize_azure_resource_graph():
    raw_azure = {
        "id": "/subscriptions/sub-123/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-db",
        "name": "nsg-db",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "eastus",
        "subscriptionId": "sub-123",
        "tags": {"Team": "db-admins"},
        "properties": {
            "securityRules": [
                {
                    "properties": {
                        "sourceAddressPrefix": "0.0.0.0/0",
                        "access": "Allow",
                        "destinationPortRange": "5432",
                    }
                }
            ]
        },
    }
    asset = MultiCloudNormalizer.normalize_asset(raw_azure, "azure")
    assert asset.cloud_provider == "azure"
    assert asset.resource_type == "network.firewall"
    assert asset.owner == "db-admins"
    assert asset.exposure_level == "public"
    assert "5432" in asset.network_config["open_ports"]


def test_normalize_malformed_and_boundary_inputs():
    empty_raw = {}
    asset = MultiCloudNormalizer.normalize_asset(empty_raw, "aws")
    assert asset.cloud_provider == "aws"
    assert asset.exposure_level == "private"
    assert asset.owner is None
    assert asset.resource_type == "aws.custom_resource"
