from typing import Any

from identitybridge.infrastructure.audit_models import AuditEvent
from identitybridge.infrastructure.database import SessionLocal

SAFE_DETAIL_KEYS = {"username", "enabled", "role"}


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
    """Persist a security audit event without sensitive request data."""

    if not actor_sub:
        raise ValueError("Audit actor subject is required")

    if outcome not in {"success", "failure"}:
        raise ValueError("Invalid audit outcome")

    safe_details = {
        key: value
        for key, value in (details or {}).items()
        if key in SAFE_DETAIL_KEYS
        and isinstance(value, (str, bool, int, float))
    }

    db = SessionLocal()

    try:
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
        db.commit()

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
