"""Audit logging service capturing operations, mutations, and security events."""
from datetime import datetime, timezone
import json
import uuid
from typing import Any, Optional
from sqlalchemy.orm import Session
from app.models.entities import AuditLogRecord
from app.models.schemas import AuditLogEntry


class AuditService:
    @staticmethod
    def record_event(
        db: Session,
        actor: str,
        role: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
    ) -> AuditLogRecord:
        """Create and persist a structured audit event."""
        entry = AuditLogRecord(
            id=str(uuid.uuid4()),
            actor=actor,
            role=role,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details_json=json.dumps(details or {}),
            created_at=datetime.now(timezone.utc),
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry

    @staticmethod
    def get_events(
        db: Session,
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> list[AuditLogEntry]:
        """Query audit log events with optional filtering and pagination."""
        query = db.query(AuditLogRecord)
        if action:
            query = query.filter(AuditLogRecord.action == action)
        if resource_type:
            query = query.filter(AuditLogRecord.resource_type == resource_type)

        records = query.order_by(AuditLogRecord.created_at.desc()).offset(offset).limit(limit).all()

        return [
            AuditLogEntry(
                id=r.id,
                actor=r.actor,
                role=r.role,
                action=r.action,
                resource_type=r.resource_type,
                resource_id=r.resource_id,
                details=json.loads(r.details_json) if r.details_json else {},
                created_at=r.created_at,
            )
            for r in records
        ]
