"""Ground-truth benchmark dataset for multi-cloud configuration drift risk classification."""
from typing import Any

_D = {"aws": ("us-east-1", "111222333444"), "gcp": ("us-central1", "fintech-prod"), "azure": ("eastus", "sub-az-1")}


def _c(cid, name, rtype, cloud, owner, exp, pub=None, ports=None, admin=False, tags=None, score=0.5, sev="MEDIUM", deltas=None, exp_esc=False, iam_esc=False, own_drift=False):
    r, a = _D[cloud]
    rid = f"arn:aws:{rtype}:{r}:{a}:{name}" if cloud == "aws" else (f"//{rtype}.googleapis.com/projects/{a}/{name}" if cloud == "gcp" else f"/subscriptions/{a}/resourceGroups/prod-rg/providers/{rtype}/{name}")
    return {
        "id": cid, "resource_id": rid, "resource_name": name, "resource_type": rtype,
        "cloud_provider": cloud, "region": r, "account_id": a, "owner": owner, "exposure_level": exp,
        "network_config": {"public_ip": pub, "open_ports": ports or []},
        "iam_config": {"has_admin_privilege": admin}, "tags": tags or {},
        "deltas": deltas or [], "exposure_escalated": exp_esc, "iam_escalated": iam_esc,
        "owner_drifted": own_drift, "risk_score": score, "ground_truth_severity": sev,
    }


BENCHMARK_DATASET: list[dict[str, Any]] = [
    # CRITICAL (8)
    _c("case-001", "customer-data-lake", "storage.bucket", "aws", "sec-team", "public", "54.210.12.33", ["0.0.0.0/0:443"], False, {"Env": "prod"}, 0.95, "CRITICAL", [{"field": "exposure_level", "old_value": "private", "new_value": "public"}], exp_esc=True),
    _c("case-002", "k8s-master-01", "compute.instance", "gcp", "platform-team", "public", "35.200.12.44", ["0.0.0.0/0:6443"], True, {"owner": "platform-team"}, 0.98, "CRITICAL", [{"field": "exposure_level", "old_value": "internal", "new_value": "public"}], exp_esc=True, iam_esc=True),
    _c("case-003", "vm-payment-gw", "compute.instance", "azure", "fintech-core", "public", "20.120.30.90", ["0.0.0.0/0:22"], True, {}, 0.96, "CRITICAL", [{"field": "network_config.open_ports", "old_value": ["10.0.0.0/8:22"], "new_value": ["0.0.0.0/0:22"]}], exp_esc=True, iam_esc=True),
    _c("case-004", "bastion-host-01", "compute.instance", "aws", "infra-ops", "public", "54.210.40.11", ["0.0.0.0/0:22"], True, {"Owner": "infra-ops"}, 0.94, "CRITICAL", [{"field": "iam_config.has_admin_privilege", "old_value": False, "new_value": True}], exp_esc=True, iam_esc=True),
    _c("case-005", "rds-billing-db", "database.relational", "aws", "finance-team", "public", "54.210.40.11", ["0.0.0.0/0:5432"], False, {}, 0.92, "CRITICAL", [{"field": "exposure_level", "old_value": "private", "new_value": "public"}], exp_esc=True),
    _c("case-006", "sql-analytics", "database.relational", "gcp", "data-eng", "public", "35.190.44.12", ["0.0.0.0/0:3306"], False, {"owner": "data-eng"}, 0.90, "CRITICAL", [{"field": "exposure_level", "old_value": "internal", "new_value": "public"}], exp_esc=True),
    _c("case-007", "audit-archive", "storage.bucket", "azure", "sec-team", "public", "20.120.40.15", ["0.0.0.0/0:443"], False, {}, 0.88, "CRITICAL", [{"field": "exposure_level", "old_value": "private", "new_value": "public"}], exp_esc=True),
    _c("case-008", "sec-admin-role", "iam.role", "aws", None, "private", None, [], True, {}, 0.86, "CRITICAL", [{"field": "iam_config.has_admin_privilege", "old_value": False, "new_value": True}], iam_esc=True, own_drift=True),

    # HIGH (8)
    _c("case-009", "confidential-ml", "storage.bucket", "aws", None, "private", None, [], False, {"Confidential": "true"}, 0.68, "HIGH", [{"field": "owner", "old_value": "ml", "new_value": None}], own_drift=True),
    _c("case-010", "k8s-workers", "compute.instance", "gcp", "platform-team", "internal", None, [], True, {"owner": "platform-team"}, 0.66, "HIGH", [{"field": "iam_config.has_admin_privilege", "old_value": False, "new_value": True}], iam_esc=True),
    _c("case-011", "jumpbox-az", "compute.instance", "azure", "infra-ops", "internal", None, ["10.0.0.0/8:22"], False, {}, 0.64, "HIGH", [{"field": "network_config.open_ports", "old_value": [], "new_value": ["10.0.0.0/8:22"]}]),
    _c("case-012", "rds-user-db", "database.relational", "aws", None, "internal", None, ["10.0.0.0/8:5432"], False, {}, 0.65, "HIGH", [{"field": "owner", "old_value": "db", "new_value": None}], own_drift=True),
    _c("case-013", "bigquery-vault", "database.relational", "gcp", None, "internal", None, [], False, {}, 0.62, "HIGH", [{"field": "owner", "old_value": "data", "new_value": None}], own_drift=True),
    _c("case-014", "core-nsg", "network.firewall", "azure", "sec-team", "internal", None, ["10.0.0.0/8:445"], False, {}, 0.60, "HIGH", [{"field": "network_config.open_ports", "old_value": [], "new_value": ["10.0.0.0/8:445"]}]),
    _c("case-015", "web-portal", "compute.instance", "aws", "frontend-team", "public", "54.210.50.20", ["0.0.0.0/0:80", "0.0.0.0/0:443"], False, {"Owner": "frontend-team"}, 0.58, "HIGH", [{"field": "exposure_level", "old_value": "internal", "new_value": "public"}], exp_esc=True),
    _c("case-016", "api-gateway", "compute.instance", "gcp", "api-team", "public", "35.190.80.10", ["0.0.0.0/0:443"], False, {"owner": "api-team"}, 0.56, "HIGH", [{"field": "exposure_level", "old_value": "internal", "new_value": "public"}], exp_esc=True),

    # MEDIUM (8)
    _c("case-017", "batch-vm", "compute.instance", "aws", None, "private", None, [], False, {}, 0.38, "MEDIUM", [{"field": "owner", "old_value": "batch", "new_value": None}], own_drift=True),
    _c("case-018", "log-node", "compute.instance", "gcp", None, "private", None, [], False, {}, 0.36, "MEDIUM", [{"field": "owner", "old_value": "ops", "new_value": None}], own_drift=True),
    _c("case-019", "agent-vm", "compute.instance", "azure", "sre-team", "internal", None, ["10.0.0.0/8:8080"], False, {}, 0.34, "MEDIUM", [{"field": "network_config.open_ports", "old_value": [], "new_value": ["10.0.0.0/8:8080"]}]),
    _c("case-020", "raw-telemetry", "storage.bucket", "aws", "telemetry-team", "private", None, [], False, {"Retention": "30d"}, 0.32, "MEDIUM", [{"field": "lifecycle", "old_value": "90d", "new_value": "30d"}]),
    _c("case-021", "temp-artifacts", "storage.bucket", "gcp", "build-team", "private", None, [], False, {}, 0.30, "MEDIUM", [{"field": "lifecycle", "old_value": "7d", "new_value": "14d"}]),
    _c("case-022", "diagnostics-blob", "storage.bucket", "azure", "diag-ops", "private", None, [], False, {}, 0.28, "MEDIUM", [{"field": "tls_version", "old_value": "1.2", "new_value": "1.3"}]),
    _c("case-023", "nsg-metrics", "network.firewall", "aws", "sre-team", "internal", None, ["10.0.0.0/8:9090"], False, {}, 0.31, "MEDIUM", [{"field": "network_config.open_ports", "old_value": [], "new_value": ["10.0.0.0/8:9090"]}]),
    _c("case-024", "cache-redis", "compute.instance", "gcp", "cache-team", "internal", None, [], False, {}, 0.29, "MEDIUM", [{"field": "machine_type", "old_value": "e2-small", "new_value": "e2-medium"}]),

    # LOW (8)
    _c("case-025", "docs-static", "storage.bucket", "aws", "docs-team", "private", None, [], False, {"Release": "v1.2", "Owner": "docs-team"}, 0.08, "LOW", [{"field": "tags.Release", "old_value": "v1.1", "new_value": "v1.2"}]),
    _c("case-026", "vm-worker", "compute.instance", "aws", "dev-team", "private", None, [], False, {"Environment": "dev", "Owner": "dev-team"}, 0.06, "LOW", [{"field": "tags.Environment", "old_value": "sandbox", "new_value": "dev"}]),
    _c("case-027", "k8s-canary", "compute.instance", "gcp", "infra-team", "private", None, [], False, {"owner": "infra-team", "tier": "canary"}, 0.05, "LOW", [{"field": "tags.tier", "old_value": "alpha", "new_value": "canary"}]),
    _c("case-028", "build-runner", "compute.instance", "azure", "ci-team", "private", None, [], False, {"CostCenter": "eng-dev", "Owner": "ci-team"}, 0.04, "LOW", [{"field": "tags.CostCenter", "old_value": "eng", "new_value": "eng-dev"}]),
    _c("case-029", "rds-sandbox", "database.relational", "aws", "db-admins", "private", None, [], False, {"Backup": "weekly", "Owner": "db-admins"}, 0.07, "LOW", [{"field": "tags.Backup", "old_value": "daily", "new_value": "weekly"}]),
    _c("case-030", "cloudsql-test", "database.relational", "gcp", "test-team", "private", None, [], False, {"owner": "test-team"}, 0.05, "LOW", [{"field": "maintenance_window", "old_value": "sun-0200", "new_value": "sun-0400"}]),
    _c("case-031", "nsg-icmp", "network.firewall", "azure", "sec-team", "private", None, [], False, {"Owner": "sec-team"}, 0.04, "LOW", [{"field": "description", "old_value": "allow icmp", "new_value": "allow ping"}]),
    _c("case-032", "logging-helper", "compute.instance", "aws", "logging-ops", "private", None, [], False, {"Owner": "logging-ops"}, 0.03, "LOW", [{"field": "detailed_monitoring", "old_value": False, "new_value": True}]),
]