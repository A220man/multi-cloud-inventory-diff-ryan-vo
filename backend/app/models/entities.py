"""SQLAlchemy entity models for persistent multi-cloud inventory storage."""
from datetime import datetime, timezone
import json
from typing import Any
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


def utc_now() -> datetime:
    """Return timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class SnapshotRecord(Base):
    __tablename__ = "snapshots"

    id = Column(String(36), primary_key=True, index=True)
    name = Column(String(128), nullable=False)
    cloud_provider = Column(String(32), nullable=False, index=True)  # aws, gcp, azure, or multi-cloud
    source_type = Column(String(64), nullable=False)  # config-export, asset-inventory, resource-graph
    asset_count = Column(Integer, default=0, nullable=False)
    description = Column(String(255), nullable=True)
    created_by = Column(String(128), nullable=False, default="operator")
    created_at = Column(DateTime, default=utc_now, nullable=False)

    assets = relationship("AssetRecord", back_populates="snapshot", cascade="all, delete-orphan")


class AssetRecord(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, index=True)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False, index=True)
    resource_id = Column(String(255), nullable=False, index=True)
    resource_name = Column(String(255), nullable=False)
    resource_type = Column(String(128), nullable=False, index=True)
    cloud_provider = Column(String(32), nullable=False, index=True)
    region = Column(String(64), nullable=False)
    account_id = Column(String(128), nullable=False)
    owner = Column(String(128), nullable=True, index=True)
    exposure_level = Column(String(32), nullable=False, default="private", index=True)  # private, internal, public
    network_config_json = Column(Text, nullable=False, default="{}")
    iam_config_json = Column(Text, nullable=False, default="{}")
    tags_json = Column(Text, nullable=False, default="{}")
    raw_metadata_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=utc_now, nullable=False)

    snapshot = relationship("SnapshotRecord", back_populates="assets")

    def _j(self, val: str) -> Any:
        return json.loads(val) if val else {}

    def get_network_config(self) -> dict[str, Any]:
        return self._j(self.network_config_json)

    def get_iam_config(self) -> dict[str, Any]:
        return self._j(self.iam_config_json)

    def get_tags(self) -> dict[str, str]:
        return self._j(self.tags_json)

    def get_raw_metadata(self) -> dict[str, Any]:
        return self._j(self.raw_metadata_json)


class DiffRecord(Base):
    __tablename__ = "snapshot_diffs"

    id = Column(String(36), primary_key=True, index=True)
    base_snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False, index=True)
    target_snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False, index=True)
    added_count = Column(Integer, default=0, nullable=False)
    removed_count = Column(Integer, default=0, nullable=False)
    modified_count = Column(Integer, default=0, nullable=False)
    diff_payload_json = Column(Text, nullable=False)
    exposure_summary_json = Column(Text, nullable=False)
    owner_grouping_json = Column(Text, nullable=False)
    created_by = Column(String(128), nullable=False, default="operator")
    created_at = Column(DateTime, default=utc_now, nullable=False)


class EvaluationRecord(Base):
    __tablename__ = "evaluations"

    id = Column(String(36), primary_key=True, index=True)
    diff_id = Column(String(36), ForeignKey("snapshot_diffs.id"), nullable=False, index=True)
    total_evaluated = Column(Integer, default=0, nullable=False)
    high_risk_count = Column(Integer, default=0, nullable=False)
    critical_risk_count = Column(Integer, default=0, nullable=False)
    anomaly_count = Column(Integer, default=0, nullable=False)
    evaluation_payload_json = Column(Text, nullable=False)
    created_by = Column(String(128), nullable=False, default="operator")
    created_at = Column(DateTime, default=utc_now, nullable=False)


class AuditLogRecord(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, index=True)
    actor = Column(String(128), nullable=False)
    role = Column(String(64), nullable=False)
    action = Column(String(128), nullable=False, index=True)
    resource_type = Column(String(64), nullable=False)
    resource_id = Column(String(128), nullable=True)
    details_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=utc_now, nullable=False)
