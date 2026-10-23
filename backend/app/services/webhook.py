"""HMAC-authenticated webhook ingestion for real-time cloud inventory change notifications."""
import hmac
import hashlib
import time
import json
from typing import Any, Optional
from datetime import datetime, timezone

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.models.schemas import CanonicalAsset
from app.services.normalizer import MultiCloudNormalizer
from app.services.diff_engine import DiffEngine
from app.models.entities import SnapshotRecord, DiffRecord, AssetRecord
from app.core.config import settings


class WebhookService:
    """Handles HMAC-verified webhook ingestion and automated diff triggering."""

    # HMAC header name expected from cloud providers
    HMAC_HEADER = "X-Cloud-Inventory-Signature"
    # Timestamp header to prevent replay attacks
    TIMESTAMP_HEADER = "X-Cloud-Inventory-Timestamp"
    # Maximum allowed timestamp drift in seconds (5 minutes)
    MAX_TIMESTAMP_DRIFT = 300

    @staticmethod
    def _get_webhook_secret(provider: str) -> str:
        """Retrieve webhook secret for a cloud provider from settings."""
        secret_map = {
            "aws": settings.WEBHOOK_SECRET_AWS,
            "gcp": settings.WEBHOOK_SECRET_GCP,
            "azure": settings.WEBHOOK_SECRET_AZURE,
        }
        secret = secret_map.get(provider.lower())
        if not secret:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"No webhook secret configured for provider: {provider}"
            )
        return secret

    @classmethod
    def verify_hmac(cls, provider: str, payload: bytes, signature_header: str, timestamp_header: str) -> bool:
        """
        Verify HMAC signature and timestamp to prevent replay attacks.

        Args:
            provider: Cloud provider identifier (aws, gcp, azure)
            payload: Raw request body bytes
            signature_header: Value of X-Cloud-Inventory-Signature header
            timestamp_header: Value of X-Cloud-Inventory-Timestamp header

        Returns:
            True if signature and timestamp are valid

        Raises:
            HTTPException: If verification fails
        """
        # Verify timestamp freshness
        try:
            received_ts = int(timestamp_header)
        except (ValueError, TypeError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid timestamp header"
            )

        now = int(time.time())
        if abs(now - received_ts) > cls.MAX_TIMESTAMP_DRIFT:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Timestamp outside allowed drift window"
            )

        # Verify HMAC signature
        secret = cls._get_webhook_secret(provider)
        expected_sig = hmac.new(
            secret.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()

        # Constant-time comparison
        if not hmac.compare_digest(expected_sig, signature_header):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid HMAC signature"
            )

        return True

    @classmethod
    async def ingest_webhook(
        cls,
        provider: str,
        request: Request,
        db: Session,
        user_id: Optional[str] = None
    ) -> dict[str, Any]:
        """
        Process incoming webhook: verify HMAC, normalize assets, create snapshot, trigger diff.

        Args:
            provider: Cloud provider (aws, gcp, azure)
            request: FastAPI Request object
            db: Database session
            user_id: Optional user ID for audit logging

        Returns:
            Dict with snapshot_id, diff_id (if triggered), and asset count
        """
        # Read raw body for HMAC verification
        body = await request.body()

        # Extract headers
        signature = request.headers.get(cls.HMAC_HEADER)
        timestamp = request.headers.get(cls.TIMESTAMP_HEADER)

        if not signature or not timestamp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing required HMAC or timestamp headers"
            )

        # Verify HMAC
        cls.verify_hmac(provider, body, signature, timestamp)

        # Parse and normalize payload
        try:
            raw_payload = json.loads(body.decode())
        except json.JSONDecodeError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid JSON payload: {str(e)}"
            )

        # Handle both single asset and array of assets
        assets_list = raw_payload if isinstance(raw_payload, list) else [raw_payload]

        # Normalize all assets
        normalized_assets: list[CanonicalAsset] = []
        for raw_asset in assets_list:
            try:
                asset = MultiCloudNormalizer.normalize_asset(raw_asset, default_provider=provider)
                normalized_assets.append(asset)
            except Exception as e:
                # Log but continue with other assets
                print(f"Failed to normalize asset: {e}")
                continue

        if not normalized_assets:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid assets in webhook payload"
            )

        # Create new snapshot with normalized assets
        import uuid
        snapshot_id = str(uuid.uuid4())
        snapshot = SnapshotRecord(
            id=snapshot_id,
            name=f"webhook-{provider}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            cloud_provider=provider,
            source_type=f"{provider}-webhook",
            asset_count=len(normalized_assets),

            created_at=datetime.now(timezone.utc),
        )
        db.add(snapshot)
        db.flush()
        # Persist assets
        for asset in normalized_assets:
            asset_rec = AssetRecord(
                id=str(uuid.uuid4()),
                snapshot_id=snapshot_id,
                resource_id=asset.resource_id,
                resource_name=asset.resource_name,
                resource_type=asset.resource_type,
                cloud_provider=asset.cloud_provider,
                region=asset.region,
                account_id=asset.account_id,
                owner=asset.owner,
                exposure_level=asset.exposure_level,
                network_config_json=json.dumps(asset.network_config),
                iam_config_json=json.dumps(asset.iam_config),
                tags_json=json.dumps(asset.tags),
                created_at=datetime.now(timezone.utc),
            )
            db.add(asset_rec)

        # Find latest baseline snapshot for same provider (excluding this one)
        baseline = db.query(SnapshotRecord).filter(
            SnapshotRecord.cloud_provider == provider,
            SnapshotRecord.id != snapshot_id
        ).order_by(SnapshotRecord.created_at.desc()).first()

        diff_id = None
        if baseline:
            # Get baseline assets
            baseline_assets = db.query(AssetRecord).filter(
                AssetRecord.snapshot_id == baseline.id
            ).all()
            base_canonical = [
                CanonicalAsset(
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
                )
                for a in baseline_assets
            ]

            # Compute diff
            diff_items, exposure_summary, owner_grouping = DiffEngine.compute_diff(
                base_canonical, normalized_assets
            )

            # Only create diff record if there are actual changes
            if diff_items:
                diff_id = str(uuid.uuid4())
                diff_rec = DiffRecord(
                    id=diff_id,
                    base_snapshot_id=baseline.id,
                    target_snapshot_id=snapshot_id,
                    diff_payload_json=json.dumps([item.model_dump() for item in diff_items]),
                    exposure_summary_json=json.dumps(exposure_summary),
                    owner_grouping_json=json.dumps([g.model_dump() for g in owner_grouping]),
                    created_at=datetime.now(timezone.utc),
                )
                db.add(diff_rec)

        db.commit()

        return {
            "snapshot_id": snapshot_id,
            "diff_id": diff_id,
            "assets_processed": len(normalized_assets),
            "baseline_snapshot_id": baseline.id if baseline else None,
            "changes_detected": diff_id is not None,
        }