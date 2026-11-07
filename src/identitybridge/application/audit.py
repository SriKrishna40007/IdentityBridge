from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, status

from identitybridge.infrastructure.audit_service import record_audit_event

AuditWriter = Callable[..., None]


def get_audit_writer() -> AuditWriter:
    """Provide the production audit persistence function."""
    return record_audit_event


def write_lifecycle_audit(
    writer: AuditWriter,
    *,
    actor: dict[str, Any],
    action: str,
    target_user_id: str | None,
    outcome: str,
    request_id: str | None,
    details: dict[str, Any] | None = None,
) -> None:
    """Persist a lifecycle audit event or report an audit failure."""

    actor_sub = actor.get("sub")

    if not isinstance(actor_sub, str) or not actor_sub:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated actor identity is unavailable",
        )

    username = actor.get("preferred_username")

    try:
        writer(
            actor_sub=actor_sub,
            actor_username=username if isinstance(username, str) else None,
            action=action,
            target_user_id=target_user_id,
            outcome=outcome,
            request_id=request_id,
            details=details,
        )
    except Exception as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Identity-provider operation may have completed, "
                "but audit persistence failed"
            ),
        ) from error
