from typing import Any

from sqlalchemy.orm import Session

from identitybridge.infrastructure.audit_models import AuditEvent
from identitybridge.infrastructure.database import SessionLocal

SAFE_DETAIL_KEYS = {
    "username",
    "enabled",
    "role",
    "status",
    "duration_minutes",
}


def add_audit_event(
    db: Session,
    *,
    actor_sub: str,
    actor_username: str | None,
    action: str,
    target_user_id: str | None,
    outcome: str,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    """Add an audit event to the caller's transaction without committing."""
    if not actor_sub:
        raise ValueError("Audit actor subject is required")

    if outcome not in {"success", "failure"}:
        raise ValueError("Invalid audit outcome")

    safe_details = {
        key: value
        for key, value in (details or {}).items()
        if key in SAFE_DETAIL_KEYS and isinstance(value, (str, bool, int, float))
    }

    event = AuditEvent(
        actor_sub=actor_sub[:255],
        actor_username=actor_username[:100] if actor_username else None,
        action=action[:100],
        target_user_id=target_user_id[:255] if target_user_id else None,
        outcome=outcome,
        request_id=request_id[:100] if request_id else None,
        details=safe_details,
    )

    db.add(event)
    return event


def record_audit_event(
    *,
    actor_sub: str,
    actor_username: str | None,
    action: str,
    target_user_id: str | None,
    outcome: str,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Persist a standalone security audit event."""
    db = SessionLocal()

    try:
        add_audit_event(
            db,
            actor_sub=actor_sub,
            actor_username=actor_username,
            action=action,
            target_user_id=target_user_id,
            outcome=outcome,
            request_id=request_id,
            details=details,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
