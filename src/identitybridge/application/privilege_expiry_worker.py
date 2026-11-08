from datetime import UTC, datetime

from sqlalchemy.orm import Session

from identitybridge.application.privilege_lifecycle import (
    claim_expired_privileges,
    complete_privilege_revocation,
)
from identitybridge.infrastructure.keycloak.admin_client import (
    KeycloakAdminClient,
)


async def process_expired_privileges(
    db: Session,
    admin: KeycloakAdminClient,
    *,
    client_id: str,
    batch_size: int = 50,
    now: datetime | None = None,
) -> dict[str, int]:
    """Process individually claimed expirations and due revocation retries.

    Each request is claimed immediately before its Keycloak operations.
    This gives every request its own recovery lease instead of starting
    a large batch with one shared lease timestamp.
    """
    if now is not None and now.tzinfo is None:
        raise ValueError("Worker timestamp must be timezone-aware")

    if not 1 <= batch_size <= 500:
        raise ValueError("Batch size must be between 1 and 500")

    result = {
        "processed": 0,
        "expired": 0,
        "retry_scheduled": 0,
        "skipped": 0,
        "manual_reconciliation": 0,
    }

    for _ in range(batch_size):
        claim_time = now if now is not None else datetime.now(UTC)

        claims = claim_expired_privileges(
            db,
            now=claim_time,
            batch_size=1,
        )

        if not claims:
            break

        request_id, action, target_user_id, role_name = claims[0]
        result["processed"] += 1

        if action == "manual":
            result["manual_reconciliation"] += 1
            continue

        if action == "expired":
            result["expired"] += 1
            continue

        if action != "revoke_pending":
            result["skipped"] += 1
            continue

        # Only identity-provider errors are converted into retry outcomes.
        # Database completion errors deliberately propagate to the caller.
        try:
            roles = await admin.get_user_client_roles(
                target_user_id,
                client_id,
            )

            role_exists = any(role.get("name") == role_name for role in roles)

            if role_exists:
                await admin.remove_client_role(
                    target_user_id,
                    client_id,
                    role_name,
                )

                roles = await admin.get_user_client_roles(
                    target_user_id,
                    client_id,
                )

                role_exists = any(role.get("name") == role_name for role in roles)

            role_absent = not role_exists

        except Exception:
            # An ambiguous provider result is not treated as successful removal.
            role_absent = False

        completion_time = now if now is not None else datetime.now(UTC)

        updated = complete_privilege_revocation(
            db,
            request_id,
            role_absent=role_absent,
            now=completion_time,
        )

        if updated.status == "expired":
            result["expired"] += 1
        elif updated.status == "revoke_failed":
            result["retry_scheduled"] += 1
        else:
            result["skipped"] += 1

    return result
