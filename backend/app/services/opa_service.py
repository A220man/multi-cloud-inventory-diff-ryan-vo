"""Open Policy Agent Rego compliance evaluation for canonical assets."""
import json
from typing import Any
from opa import OPAClient


class OPAService:
    """Handles OPA policy management and evaluation against canonical assets."""

    def __init__(self, host: str = "localhost", port: int = 8181):
        self.client = OPAClient(host=host, port=port, version="v1")

    def check_connection(self) -> bool:
        """Verify OPA server is reachable."""
        try:
            return self.client.check_connection()
        except Exception:
            return False

    def load_policy(self, policy_id: str, rego_content: str) -> bool:
        """
        Load a Rego policy into OPA.

        Args:
            policy_id: Unique identifier for the policy (used as package path)
            rego_content: Raw Rego policy source code

        Returns:
            True if policy loaded successfully
        """
        try:
            self.client.update_policy_from_string(
                policy_id=policy_id,
                body=rego_content,
                path=["policies", policy_id],
            )
            return True
        except Exception as e:
            print(f"Failed to load policy {policy_id}: {e}")
            return False

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy from OPA."""
        try:
            self.client.delete_policy(policy_id=policy_id)
            return True
        except Exception:
            return False

    def list_policies(self) -> list[str]:
        """List all loaded policy IDs."""
        try:
            policies = self.client.policies_list()
            return [p for p in policies if p.startswith("policies/")]
        except Exception:
            return []

    def evaluate_policy(
        self,
        policy_id: str,
        input_data: dict[str, Any],
        rule: str = "violation"
    ) -> dict[str, Any]:
        """
        Evaluate a policy against input data.

        Args:
            policy_id: Policy identifier
            input_data: Input document for policy evaluation
            rule: Rule name to evaluate (default: "violation")

        Returns:
            Policy evaluation result with violations
        """
        try:
            result = self.client.check_policy(
                policy_name=policy_id,
                rule_name=rule,
                input_data=input_data,
            )
            return {
                "policy_id": policy_id,
                "result": result.get("result", {}),
                "violations": result.get("result", []),
                "allowed": len(result.get("result", [])) == 0,
            }
        except Exception as e:
            return {
                "policy_id": policy_id,
                "result": {},
                "violations": [],
                "allowed": True,
                "error": str(e),
            }

    def evaluate_all_policies(
        self,
        input_data: dict[str, Any],
        rule: str = "violation"
    ) -> list[dict[str, Any]]:
        """
        Evaluate all loaded policies against input data.

        Args:
            input_data: Input document for policy evaluation
            rule: Rule name to evaluate

        Returns:
            List of policy evaluation results
        """
        policies = self.list_policies()
        results = []
        for policy_id in policies:
            result = self.evaluate_policy(policy_id, input_data, rule)
            results.append(result)
        return results

    @staticmethod
    def canonical_asset_to_opa_input(assets: list[dict]) -> dict[str, Any]:
        """Convert canonical assets to OPA input format."""
        return {"assets": assets}

    @staticmethod
    def diff_item_to_opa_input(diff_items: list[dict]) -> dict[str, Any]:
        """Convert diff items to OPA input format."""
        return {"diffs": diff_items}


# Default Rego policies for common compliance checks
DEFAULT_POLICIES = {
    "public_exposure": """
package policies.public_exposure

default violation = []

violation[msg] {
    asset := input.assets[_]
    asset.exposure_level == "public"
    msg := sprintf("Resource %s (%s) has public exposure", [asset.resource_name, asset.resource_id])
}
""",
    "unowned_resources": """
package policies.unowned_resources

default violation = []

violation[msg] {
    asset := input.assets[_]
    asset.owner == ""
    msg := sprintf("Resource %s (%s) has no owner assigned", [asset.resource_name, asset.resource_id])
}
""",
    "overly_permissive_iam": """
package policies.overly_permissive_iam

default violation = []

violation[msg] {
    asset := input.assets[_]
    iam := asset.iam_config
    iam.bindings[_].role == "roles/owner"
    msg := sprintf("Resource %s (%s) has overly permissive IAM binding (roles/owner)", [asset.resource_name, asset.resource_id])
}

violation[msg] {
    asset := input.assets[_]
    iam := asset.iam_config
    iam.bindings[_].role == "*"
    msg := sprintf("Resource %s (%s) has wildcard IAM role", [asset.resource_name, asset.resource_id])
}
""",
    "unencrypted_storage": """
package policies.unencrypted_storage

default violation = []

violation[msg] {
    asset := input.assets[_]
    asset.resource_type == "aws.s3_bucket"
    not asset.network_config.encryption.enabled
    msg := sprintf("S3 bucket %s (%s) is not encrypted", [asset.resource_name, asset.resource_id])
}

violation[msg] {
    asset := input.assets[_]
    asset.resource_type == "gcp.storage_bucket"
    not asset.network_config.encryption.default_kms_key_name
    msg := sprintf("GCS bucket %s (%s) is not encrypted", [asset.resource_name, asset.resource_id])
}
""",
    "public_s3_bucket": """
package policies.public_s3_bucket

default violation = []

violation[msg] {
    asset := input.assets[_]
    asset.resource_type == "aws.s3_bucket"
    asset.network_config.public_access_block == false
    msg := sprintf("S3 bucket %s (%s) allows public access", [asset.resource_name, asset.resource_id])
}

violation[msg] {
    asset := input.assets[_]
    asset.resource_type == "aws.s3_bucket"
    asset.iam_config.policy[_].Effect == "Allow"
    asset.iam_config.policy[_].Principal == "*"
    msg := sprintf("S3 bucket %s (%s) has public bucket policy", [asset.resource_name, asset.resource_id])
}
""",
    "security_group_open_to_world": """
package policies.security_group_open_to_world

default violation = []

violation[msg] {
    asset := input.assets[_]
    asset.resource_type == "aws.security_group"
    rule := asset.network_config.ingress_rules[_]
    rule.cidr_ipv4 == "0.0.0.0/0"
    rule.from_port <= 22
    rule.to_port >= 22
    msg := sprintf("Security group %s (%s) allows SSH from 0.0.0.0/0", [asset.resource_name, asset.resource_id])
}

violation[msg] {
    asset := input.assets[_]
    asset.resource_type == "aws.security_group"
    rule := asset.network_config.ingress_rules[_]
    rule.cidr_ipv4 == "0.0.0.0/0"
    rule.from_port <= 3389
    rule.to_port >= 3389
    msg := sprintf("Security group %s (%s) allows RDP from 0.0.0.0/0", [asset.resource_name, asset.resource_id])
}
""",
    "diff_exposure_escalation": """
package policies.diff_exposure_escalation

default violation = []

violation[msg] {
    diff := input.diffs[_]
    diff.diff_type == "modified"
    diff.exposure_escalated == true
    msg := sprintf("Resource %s (%s) exposure escalated from %s to %s", [diff.resource_name, diff.resource_id, diff.old_exposure, diff.new_exposure])
}
""",
    "diff_unowned_new_resource": """
package policies.diff_unowned_new_resource

default violation = []

violation[msg] {
    diff := input.diffs[_]
    diff.diff_type == "added"
    diff.owner == ""
    msg := sprintf("Newly added resource %s (%s) has no owner", [diff.resource_name, diff.resource_id])
}
""",
}


def load_default_policies(opa_service: OPAService) -> dict[str, bool]:
    """Load all default policies into OPA."""
    results = {}
    for policy_id, rego in DEFAULT_POLICIES.items():
        results[policy_id] = opa_service.load_policy(policy_id, rego)
    return results
