from uuid import UUID

from sqlalchemy.orm import Session

from identitybridge.application.privilege_lifecycle import (
    activate_privilege_grant,
    prepare_privilege_grant,
    record_ambiguous_grant,
    record_preexisting_role,
)
from identitybridge.infrastructure.keycloak.admin_client import (
    KeycloakAdminClient,
)
from identitybridge.infrastructure.privilege_request_models import (
    PrivilegeRequest,
)


async def grant_approved_privilege(
    db: Session,
    admin: KeycloakAdminClient,
    *,
    request_id: UUID,
    client_id: str,
    exclusive_role_writer: bool = False,
) -> PrivilegeRequest:
    """Grant an approved role and verify the resulting Keycloak assignment.

    Automatic ownership tracking requires the IdentityBridge service account
    to be the exclusive writer of the managed privileged role assignments.
    """
    item = prepare_privilege_grant(db, request_id)

    try:
        roles = await admin.get_user_client_roles(
            item.target_user_id,
            client_id,
        )
    except Exception:
        return record_ambiguous_grant(db, request_id)

    role_exists = any(role.get("name") == item.role_name for role in roles)

    record_preexisting_role(
        db,
        request_id,
        role_exists=role_exists,
    )

    if role_exists:
        return activate_privilege_grant(
            db,
            request_id,
            granted_by_jit=False,
        )

    if not exclusive_role_writer:
        return record_ambiguous_grant(db, request_id)

    try:
        await admin.assign_client_role(
            item.target_user_id,
            client_id,
            item.role_name,
        )

        verified_roles = await admin.get_user_client_roles(
            item.target_user_id,
            client_id,
        )

    except Exception:
        return record_ambiguous_grant(db, request_id)

    assignment_verified = any(role.get("name") == item.role_name for role in verified_roles)

    if not assignment_verified:
        return record_ambiguous_grant(db, request_id)

    return activate_privilege_grant(
        db,
        request_id,
        granted_by_jit=True,
    )
