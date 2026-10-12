"""Normalization engine translating heterogeneous AWS, GCP, and Azure asset exports into CanonicalAsset models."""
from typing import Any
from app.models.schemas import CanonicalAsset


def _parse_tags(raw: dict[str, Any], nested_cfg: dict[str, Any] | None = None) -> tuple[dict[str, str], str | None]:
    raw_tags = raw.get("tags") or raw.get("Tags") or raw.get("labels") or {}
    if not raw_tags and nested_cfg:
        raw_tags = nested_cfg.get("labels") or nested_cfg.get("tags") or {}
    tags: dict[str, str] = {}
    if isinstance(raw_tags, list):
        for item in raw_tags:
            if isinstance(item, dict):
                k = item.get("key") or item.get("Key")
                v = item.get("value") or item.get("Value")
                if k is not None:
                    tags[str(k)] = str(v)
    elif isinstance(raw_tags, dict):
        tags = {str(k): str(v) for k, v in raw_tags.items()}
    owner = tags.get("Owner") or tags.get("owner") or tags.get("team") or tags.get("Team")
    return tags, owner


class MultiCloudNormalizer:
    @staticmethod
    def normalize_asset(raw: dict[str, Any], default_provider: str = "aws") -> CanonicalAsset:
        if "assetType" in raw or ("name" in raw and str(raw.get("name", "")).startswith("//")):
            return MultiCloudNormalizer._normalize_gcp(raw)
        if "type" in raw and ("Microsoft." in raw.get("type", "") or "subscriptionId" in raw):
            return MultiCloudNormalizer._normalize_azure(raw)
        if "resourceType" in raw or "awsRegion" in raw or "accountId" in raw or ("arn" in raw):
            return MultiCloudNormalizer._normalize_aws(raw)
        if default_provider == "gcp":
            return MultiCloudNormalizer._normalize_gcp(raw)
        if default_provider == "azure":
            return MultiCloudNormalizer._normalize_azure(raw)
        return MultiCloudNormalizer._normalize_aws(raw)

    @staticmethod
    def _normalize_aws(raw: dict[str, Any]) -> CanonicalAsset:
        config = raw.get("configuration") or raw.get("Configuration") or raw.get("properties") or {}
        raw_type = raw.get("resourceType") or raw.get("type") or "AWS::Generic::Resource"
        region = raw.get("awsRegion") or raw.get("region") or raw.get("Region") or "us-east-1"
        account_id = str(raw.get("accountId") or raw.get("account") or raw.get("OwnerId") or "123456789012")
        tags, owner = _parse_tags(raw)
        public_ip = config.get("publicIpAddress") or config.get("PublicIp") or raw.get("public_ip")
        is_public = bool(public_ip)
        open_ports = []
        for perm in (config.get("ipPermissions") or config.get("IpPermissions") or []):
            if isinstance(perm, dict):
                fp = perm.get("FromPort")
                tp = perm.get("ToPort", fp)
                if fp is not None:
                    open_ports.append(f"{fp}-{tp}" if fp != tp else str(fp))
        if "s3" in raw_type.lower() or "bucket" in raw_type.lower():
            pab = config.get("publicAccessBlockConfiguration") or {}
            if isinstance(pab, dict) and not pab.get("blockPublicAcls", True):
                is_public = True
        exposure = "public" if is_public else ("internal" if raw.get("vpc_id") or config.get("vpcId") else "private")
        iam_config: dict[str, Any] = {}
        if "iam" in raw_type.lower() or "role" in raw_type.lower():
            policies = config.get("attachedManagedPolicies") or []
            iam_config = {"has_admin_privilege": any("AdministratorAccess" in str(p) for p in policies)}
        return CanonicalAsset(
            resource_id=raw.get("resourceId") or raw.get("id") or raw.get("arn") or str(raw.get("resourceName", "unknown")),
            resource_name=raw.get("resourceName") or raw.get("resourceId") or "unknown",
            resource_type=MultiCloudNormalizer._map_resource_type(raw_type, "aws"),
            cloud_provider="aws", region=region, account_id=account_id, owner=owner,
            exposure_level=exposure, network_config={"public_ip": public_ip, "open_ports": open_ports},
            iam_config=iam_config, tags=tags, raw_metadata=raw,
        )

    @staticmethod
    def _normalize_gcp(raw: dict[str, Any]) -> CanonicalAsset:
        name = raw.get("name") or raw.get("id") or "//compute.googleapis.com/unknown"
        raw_type = raw.get("assetType") or raw.get("type") or "GCP::Generic::Resource"
        location = raw.get("location") or raw.get("region") or raw.get("zone") or "us-central1"
        project = str(raw.get("projectId") or raw.get("project") or "unknown")
        config = raw.get("resource", {}).get("data", {}) or raw.get("resource") or raw.get("configuration") or {}
        tags, owner = _parse_tags(raw, config)
        sec_cfg = config.get("securityInformation") or raw.get("securityConfig") or {}
        public_ip = sec_cfg.get("externalIps") or config.get("externalIps")
        if not public_ip and "networkInterfaces" in config:
            for iface in config.get("networkInterfaces", []):
                for ac in iface.get("accessConfigs", []):
                    if "natIP" in ac:
                        public_ip = ac["natIP"]
                        break
        if isinstance(public_ip, list):
            public_ip = public_ip[0] if public_ip else None
        open_ports = list(set(str(p) for a in sec_cfg.get("accessTypes", []) for p in a.get("ports", [])))
        is_public = bool(public_ip)
        exposure = "public" if is_public else ("internal" if raw.get("network") or config.get("network") else "private")
        iam_config: dict[str, Any] = {}
        if "iam" in raw_type.lower() or "role" in raw_type.lower():
            bindings = config.get("bindings", [])
            iam_config = {"has_admin_privilege": any("roles/Owner" in str(b) or "roles/Editor" in str(b) for b in bindings)}
        return CanonicalAsset(
            resource_id=name, resource_name=config.get("name") or name.split("/")[-1],
            resource_type=MultiCloudNormalizer._map_resource_type(raw_type, "gcp"),
            cloud_provider="gcp", region=location, account_id=project, owner=owner,
            exposure_level=exposure, network_config={"public_ip": public_ip, "open_ports": open_ports},
            iam_config=iam_config, tags=tags, raw_metadata=raw,
        )

    @staticmethod
    def _normalize_azure(raw: dict[str, Any]) -> CanonicalAsset:
        rid = raw.get("id") or "/subscriptions/unknown/resourceGroups/unknown"
        raw_type = raw.get("type") or "Microsoft.Generic::Resource"
        location = raw.get("location") or raw.get("Region") or "eastus"
        parts = rid.split("/")
        subscription = str(raw.get("subscriptionId") or (parts[2] if len(parts) > 2 else "sub-az-1"))
        tags, owner = _parse_tags(raw)
        config = raw.get("properties") or raw.get("Properties") or {}
        public_ip = config.get("ipConfiguration") or config.get("ip_address")
        open_ports, is_public = [], bool(public_ip)
        for rule in config.get("securityRules", []):
            rp = rule.get("properties", {})
            if rp.get("access") == "Allow":
                src = str(rp.get("sourceAddressPrefix", ""))
                dst = rp.get("destinationPortRange")
                if src in ("0.0.0.0/0", "*"):
                    is_public = True
                    if dst:
                        open_ports.append(str(dst))
        exposure = "public" if is_public else ("internal" if raw.get("subnet") else "private")
        iam_config: dict[str, Any] = {}
        if "role" in raw_type.lower():
            roles = config.get("roleAssignments", [])
            iam_config = {"has_admin_privilege": any("Owner" in str(r) or "Contributor" in str(r) for r in roles)}
        return CanonicalAsset(
            resource_id=rid, resource_name=raw.get("name") or (rid.split("/")[-1] if "/" in rid else "unknown"),
            resource_type=MultiCloudNormalizer._map_resource_type(raw_type, "azure"),
            cloud_provider="azure", region=location, account_id=subscription, owner=owner,
            exposure_level=exposure, network_config={"public_ip": public_ip, "open_ports": open_ports},
            iam_config=iam_config, tags=tags, raw_metadata=raw,
        )

    @staticmethod
    def _map_resource_type(raw_type: str, provider: str) -> str:
        t = raw_type.lower()
        mapping = {
            "compute.instance": ["compute.instance", "instance", "virtualmachine"],
            "storage.bucket": ["storage.bucket", "bucket", "blob", "container"],
            "database.relational": ["database.relational", "rds", "sqlserver", "mysql", "postgresql"],
            "network.firewall": ["network.securitygroups", "networksecuritygroups", "securitygroup", "nsg", "firewall"],
        }
        for cat, keys in mapping.items():
            if any(k in t for k in keys):
                return cat
        if "compute" in t:
            return "compute.instance"
        if "storage" in t:
            return "storage.bucket"
        if "database" in t:
            return "database.relational"
        return f"{provider}.custom_resource"