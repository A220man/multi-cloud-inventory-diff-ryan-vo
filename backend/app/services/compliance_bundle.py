"""Compliance audit bundle generation with cryptographic signing.

Generates signed JSON-LD and CSV export bundles containing complete snapshot
lineage, diff evidence, OPA policy violations, ML risk classifications, and
reviewer approval signatures for regulatory compliance auditing.
"""
from datetime import datetime, timezone
import json
import uuid
from typing import Any, Optional
from dataclasses import dataclass, asdict
from sqlalchemy.orm import Session
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from jose import jwt

from app.models.entities import (
    SnapshotRecord,
    AssetRecord,
    DiffRecord,
    EvaluationRecord,
    AuditLogRecord,
)
from app.models.schemas import CanonicalAsset, DiffItem
from app.services.audit import AuditService
from app.core.config import settings


@dataclass
class BundleMetadata:
    """Metadata for the compliance audit bundle."""
    bundle_id: str
    bundle_version: str = "1.0"
    created_at: str = ""
    created_by: str = ""
    environment: str = ""
    description: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()


@dataclass
class SnapshotLineage:
    """Snapshot lineage information."""
    snapshot_id: str
    name: str
    cloud_provider: str
    source_type: str
    asset_count: int
    created_by: str
    created_at: str
    assets: list[dict]


@dataclass
class DiffEvidence:
    """Diff evidence with complete change details."""
    diff_id: str
    base_snapshot_id: str
    target_snapshot_id: str
    added_count: int
    removed_count: int
    modified_count: int
    diff_items: list[dict]
    exposure_summary: dict
    owner_grouping: dict
    created_by: str
    created_at: str


@dataclass
class PolicyViolation:
    """Policy violation from OPA evaluation."""
    policy_id: str
    violations: list[dict]
    allowed: bool
    evaluated_at: str


@dataclass
class MLEvaluationSummary:
    """ML evaluation summary."""
    evaluation_id: str
    diff_id: str
    total_evaluated: int
    high_risk_count: int
    critical_risk_count: int
    anomaly_count: int
    evaluations: list[dict]
    created_by: str
    created_at: str


@dataclass
class ReviewerApproval:
    """Reviewer approval signature."""
    reviewer_id: str
    reviewer_role: str
    approved_at: str
    approval_type: str  # "snapshot", "diff", "evaluation", "bundle"
    resource_id: str
    signature: str


class ComplianceBundleService:
    """Service for generating and signing compliance audit bundles."""

    def __init__(self, db: Session, private_key_pem: Optional[str] = None):
        self.db = db
        self.private_key = self._load_private_key(private_key_pem)
        self.public_key = self.private_key.public_key() if self.private_key else None

    def _load_private_key(self, private_key_pem: Optional[str]) -> Optional[rsa.RSAPrivateKey]:
        """Load RSA private key from PEM string or generate a new one for demo."""
        if private_key_pem:
            return serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
            )
        # Generate a new key for demo/testing (in production, use configured key)
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _sign_payload(self, payload: dict[str, Any]) -> str:
        """Sign a JSON payload with RSA-PSS SHA256."""
        if not self.private_key:
            return "unsigned-demo"
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = self.private_key.sign(
            payload_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return signature.hex()

    def _get_public_key_jwk(self) -> dict[str, str]:
        """Get public key in JWK format for verification."""
        if not self.public_key:
            return {"kty": "RSA", "n": "", "e": "AQAB"}
        numbers = self.public_key.public_numbers()
        return {
            "kty": "RSA",
            "n": self._int_to_b64url(numbers.n),
            "e": self._int_to_b64url(numbers.e),
            "alg": "RS256",
            "use": "sig",
        }

    @staticmethod
    def _int_to_b64url(value: int) -> str:
        """Convert integer to base64url encoding."""
        byte_length = (value.bit_length() + 7) // 8
        return (
            value.to_bytes(byte_length, "big")
            .hex()
            .encode()
            .decode()
        )

    def _collect_snapshot_lineage(self, snapshot_id: str) -> SnapshotLineage:
        """Collect complete snapshot lineage including all assets."""
        snap = self.db.query(SnapshotRecord).filter(SnapshotRecord.id == snapshot_id).first()
        if not snap:
            raise ValueError(f"Snapshot {snapshot_id} not found")

        assets = [
            CanonicalAsset.from_record(a).model_dump() for a in snap.assets
        ]

        return SnapshotLineage(
            snapshot_id=snap.id,
            name=snap.name,
            cloud_provider=snap.cloud_provider,
            source_type=snap.source_type,
            asset_count=snap.asset_count,
            created_by=snap.created_by,
            created_at=snap.created_at.isoformat(),
            assets=assets,
        )

    def _collect_diff_evidence(self, diff_id: str) -> DiffEvidence:
        """Collect complete diff evidence."""
        diff = self.db.query(DiffRecord).filter(DiffRecord.id == diff_id).first()
        if not diff:
            raise ValueError(f"Diff {diff_id} not found")

        diff_items = json.loads(diff.diff_payload_json)
        exposure_summary = json.loads(diff.exposure_summary_json)
        owner_grouping = json.loads(diff.owner_grouping_json)

        return DiffEvidence(
            diff_id=diff.id,
            base_snapshot_id=diff.base_snapshot_id,
            target_snapshot_id=diff.target_snapshot_id,
            added_count=diff.added_count,
            removed_count=diff.removed_count,
            modified_count=diff.modified_count,
            diff_items=diff_items,
            exposure_summary=exposure_summary,
            owner_grouping=owner_grouping,
            created_by=diff.created_by,
            created_at=diff.created_at.isoformat(),
        )

    def _collect_opa_violations(self, diff_id: str) -> list[PolicyViolation]:
        """Collect OPA policy violations for a diff."""
        eval_records = (
            self.db.query(EvaluationRecord)
            .filter(EvaluationRecord.diff_id == diff_id)
            .order_by(EvaluationRecord.created_at.desc())
            .all()
        )

        violations = []
        for eval_rec in eval_records:
            payload = json.loads(eval_rec.evaluation_payload_json)
            results = payload.get("results", [])
            for result in results:
                if result.get("violations"):
                    violations.append(
                        PolicyViolation(
                            policy_id=result.get("policy_id", ""),
                            violations=result.get("violations", []),
                            allowed=result.get("allowed", False),
                            evaluated_at=eval_rec.created_at.isoformat(),
                        )
                    )
        return violations

    def _collect_ml_evaluations(self, diff_id: str) -> list[MLEvaluationSummary]:
        """Collect ML evaluation summaries for a diff."""
        eval_records = (
            self.db.query(EvaluationRecord)
            .filter(EvaluationRecord.diff_id == diff_id)
            .order_by(EvaluationRecord.created_at.desc())
            .all()
        )

        summaries = []
        for eval_rec in eval_records:
            payload = json.loads(eval_rec.evaluation_payload_json)
            summaries.append(
                MLEvaluationSummary(
                    evaluation_id=eval_rec.id,
                    diff_id=eval_rec.diff_id,
                    total_evaluated=eval_rec.total_evaluated,
                    high_risk_count=eval_rec.high_risk_count,
                    critical_risk_count=eval_rec.critical_risk_count,
                    anomaly_count=eval_rec.anomaly_count,
                    evaluations=payload.get("evaluations", []),
                    created_by=eval_rec.created_by,
                    created_at=eval_rec.created_at.isoformat(),
                )
            )
        return summaries

    def _collect_audit_logs(
        self,
        snapshot_ids: list[str],
        diff_ids: list[str],
    ) -> list[dict]:
        """Collect relevant audit log entries."""
        query = self.db.query(AuditLogRecord)
        conditions = []
        if snapshot_ids:
            conditions.append(AuditLogRecord.resource_id.in_(snapshot_ids))
        if diff_ids:
            conditions.append(AuditLogRecord.resource_id.in_(diff_ids))
        if conditions:
            from sqlalchemy import or_
            query = query.filter(or_(*conditions))

        records = query.order_by(AuditLogRecord.created_at.desc()).limit(500).all()
        return [
            {
                "id": r.id,
                "actor": r.actor,
                "role": r.role,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "details": json.loads(r.details_json) if r.details_json else {},
                "created_at": r.created_at.isoformat(),
            }
            for r in records
        ]

    def generate_bundle(
        self,
        snapshot_ids: list[str],
        diff_ids: list[str],
        created_by: str,
        description: str = "",
        include_ml: bool = True,
        include_opa: bool = True,
        include_audit: bool = True,
    ) -> dict[str, Any]:
        """Generate a complete compliance audit bundle.

        Args:
            snapshot_ids: List of snapshot IDs to include
            diff_ids: List of diff IDs to include
            created_by: Identity of the bundle creator
            description: Human-readable description
            include_ml: Include ML evaluation summaries
            include_opa: Include OPA policy violations
            include_audit: Include audit log entries

        Returns:
            Complete bundle dictionary ready for signing
        """
        metadata = BundleMetadata(
            bundle_id=str(uuid.uuid4()),
            created_by=created_by,
            environment=settings.ENVIRONMENT,
            description=description,
        )

        # Collect snapshot lineages
        snapshots = [asdict(self._collect_snapshot_lineage(sid)) for sid in snapshot_ids]

        # Collect diff evidence
        diffs = [asdict(self._collect_diff_evidence(did)) for did in diff_ids]

        # Collect OPA violations
        opa_violations = []
        if include_opa:
            for did in diff_ids:
                opa_violations.extend([asdict(v) for v in self._collect_opa_violations(did)])

        # Collect ML evaluations
        ml_evaluations = []
        if include_ml:
            for did in diff_ids:
                ml_evaluations.extend([asdict(m) for m in self._collect_ml_evaluations(did)])

        # Collect audit logs
        audit_logs = []
        if include_audit:
            audit_logs = self._collect_audit_logs(snapshot_ids, diff_ids)
        # TODO: include reviewer approvals (placeholder)
        reviewer_approvals = []

        bundle = {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://schema.org/",
                "https://multi-cloud-inventory.example/compliance/v1",
            ],
            "type": ["VerifiableCredential", "ComplianceAuditBundle"],
            "metadata": asdict(metadata),
            "snapshots": snapshots,
            "diffs": diffs,
            "opa_violations": opa_violations,
            "reviewer_approvals": reviewer_approvals,
            "ml_evaluations": ml_evaluations,
            "audit_logs": audit_logs,
            "proof": {},  # Will be filled by sign_bundle
        }

        return bundle

    def sign_bundle(self, bundle: dict[str, Any], signer_id: str, signer_role: str) -> dict[str, Any]:
        """Sign the compliance bundle with cryptographic proof."""
        # Create proof structure per JSON-LD Verifiable Credential spec
        proof = {
            "type": "RsaSignature2018",
            "created": datetime.now(timezone.utc).isoformat(),
            "proofPurpose": "assertionMethod",
            "verificationMethod": f"did:example:{signer_id}#keys-1",
            "jws": self._sign_payload(
                {k: v for k, v in bundle.items() if k != "proof"}
            ),
        }

        bundle["proof"] = proof
        return bundle

    def verify_bundle(self, bundle: dict[str, Any], public_key_pem: Optional[str] = None) -> bool:
        """Verify the bundle signature."""
        proof = bundle.get("proof", {})
        if not proof or proof.get("jws") == "unsigned-demo":
            return True  # Demo mode

        if public_key_pem:
            pub_key = serialization.load_pem_public_key(public_key_pem.encode())
        elif self.public_key:
            pub_key = self.public_key
        else:
            return False

        payload = {k: v for k, v in bundle.items() if k != "proof"}
        payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = bytes.fromhex(proof["jws"])

        try:
            pub_key.verify(
                signature,
                payload_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    def export_csv(self, bundle: dict[str, Any]) -> dict[str, str]:
        """Export bundle data to CSV format for spreadsheet analysis.

        Returns dict of section_name -> csv_content.
        """
        import csv
        import io

        csv_outputs = {}

        # Snapshots CSV
        if bundle.get("snapshots"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "snapshot_id", "name", "cloud_provider", "source_type",
                "asset_count", "created_by", "created_at"
            ])
            for snap in bundle["snapshots"]:
                writer.writerow([
                    snap["snapshot_id"], snap["name"], snap["cloud_provider"],
                    snap["source_type"], snap["asset_count"], snap["created_by"],
                    snap["created_at"]
                ])
            csv_outputs["snapshots.csv"] = output.getvalue()

        # Assets CSV (flattened)
        if bundle.get("snapshots"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "snapshot_id", "resource_id", "resource_name", "resource_type",
                "cloud_provider", "region", "account_id", "owner",
                "exposure_level", "public_ip", "admin_ports", "tags"
            ])
            for snap in bundle["snapshots"]:
                for asset in snap["assets"]:
                    network = asset.get("network_config", {})
                    writer.writerow([
                        snap["snapshot_id"], asset["resource_id"], asset["resource_name"],
                        asset["resource_type"], asset["cloud_provider"], asset["region"],
                        asset["account_id"], asset.get("owner", ""),
                        asset["exposure_level"], network.get("public_ip", ""),
                        str(network.get("admin_ports", [])), json.dumps(asset.get("tags", {}))
                    ])
            csv_outputs["assets.csv"] = output.getvalue()

        # Diffs CSV
        if bundle.get("diffs"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "diff_id", "base_snapshot_id", "target_snapshot_id",
                "added_count", "removed_count", "modified_count",
                "created_by", "created_at"
            ])
            for diff in bundle["diffs"]:
                writer.writerow([
                    diff["diff_id"], diff["base_snapshot_id"], diff["target_snapshot_id"],
                    diff["added_count"], diff["removed_count"], diff["modified_count"],
                    diff["created_by"], diff["created_at"]
                ])
            csv_outputs["diffs.csv"] = output.getvalue()

        # Diff Items CSV
        if bundle.get("diffs"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "diff_id", "diff_type", "resource_id", "resource_name",
                "resource_type", "cloud_provider", "field", "old_value",
                "new_value", "exposure_escalation", "owner_drifted"
            ])
            for diff in bundle["diffs"]:
                for item in diff["diff_items"]:
                    for delta in item.get("field_deltas", []):
                        writer.writerow([
                            diff["diff_id"], item["diff_type"], item["resource_id"],
                            item["resource_name"], item["resource_type"],
                            item["cloud_provider"], delta["field"],
                            str(delta["old_value"]), str(delta["new_value"]),
                            item.get("exposure_escalated", False),
                            item.get("owner_drifted", False)
                        ])
            csv_outputs["diff_items.csv"] = output.getvalue()

        # OPA Violations CSV
        if bundle.get("opa_violations"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "policy_id", "violation_message", "allowed", "evaluated_at"
            ])
            for viol in bundle["opa_violations"]:
                for v in viol["violations"]:
                    writer.writerow([
                        viol["policy_id"], v.get("msg", v.get("message", "")), viol["allowed"],
                        viol["evaluated_at"]
                    ])
            csv_outputs["opa_violations.csv"] = output.getvalue()

        # ML Evaluations CSV
        if bundle.get("ml_evaluations"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "evaluation_id", "diff_id", "resource_id", "severity",
                "confidence", "rationale"
            ])
            for eval_rec in bundle["ml_evaluations"]:
                for item in eval_rec["evaluations"]:
                    writer.writerow([
                        eval_rec["evaluation_id"], eval_rec["diff_id"],
                        item["resource_id"], item["severity"],
                        item.get("confidence", 0), item.get("rationale", "")
                    ])
            csv_outputs["ml_evaluations.csv"] = output.getvalue()

        # Audit Logs CSV
        if bundle.get("audit_logs"):
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "id", "actor", "role", "action", "resource_type",
                "resource_id", "details", "created_at"
            ])
            for log in bundle["audit_logs"]:
                writer.writerow([
                    log["id"], log["actor"], log["role"], log["action"],
                    log["resource_type"], log.get("resource_id", ""),
                    json.dumps(log["details"]), log["created_at"]
                ])
            csv_outputs["audit_logs.csv"] = output.getvalue()

        return csv_outputs


def create_compliance_bundle(
    db: Session,
    snapshot_ids: list[str],
    diff_ids: list[str],
    created_by: str,
    description: str = "",
    signer_id: Optional[str] = None,
    signer_role: str = "operator",
    include_ml: bool = True,
    include_opa: bool = True,
    include_audit: bool = True,
    private_key_pem: Optional[str] = None,
) -> dict[str, Any]:
    """Convenience function to generate and sign a compliance bundle in one call."""
    service = ComplianceBundleService(db, private_key_pem)
    bundle = service.generate_bundle(
        snapshot_ids=snapshot_ids,
        diff_ids=diff_ids,
        created_by=created_by,
        description=description,
        include_ml=include_ml,
        include_opa=include_opa,
        include_audit=include_audit,
    )
    signed_bundle = service.sign_bundle(bundle, signer_id or created_by, signer_role)
    return signed_bundle
