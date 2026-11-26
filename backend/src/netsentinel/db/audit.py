"""Append-only audit logging helper."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from netsentinel.db.models import AuditLog


def record_audit(
    db: Session,
    *,
    action: str,
    resource_type: str,
    organization_id: str | None = None,
    actor_user_id: str | None = None,
    actor_type: str = "user",
    resource_id: str | None = None,
    ip_address: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        audit_metadata=metadata or {},
    )
    db.add(entry)
    return entry
