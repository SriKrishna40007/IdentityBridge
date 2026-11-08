from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from identitybridge.api.schemas.users import (
    RoleAssignment,
    UserCreate,
    UserStatusUpdate,
)
from identitybridge.application.audit import (
    AuditWriter,
    get_audit_writer,
    write_lifecycle_audit,
)
from identitybridge.infrastructure.keycloak.admin_client import (
    KeycloakAdminClient,
)
from identitybridge.security.authorization import get_current_user, require_roles

router = APIRouter(
    prefix="/api/v1/admin/users",
    tags=["Identity lifecycle management"],
    dependencies=[Depends(require_roles("identity-admin"))],
)

ALLOWED_ROLES = {
    "identity-admin",
    "security-analyst",
    "auditor",
    "standard-user",
}


PRIVILEGED_ROLES = {
    "identity-admin",
    "security-analyst",
    "auditor",
}


def get_admin_client(request: Request) -> KeycloakAdminClient:
    return request.app.state.keycloak_admin


def safe_user(user: dict[str, Any]) -> dict[str, Any]:
    """Return only approved, non-secret user attributes."""
    return {
        key: user[key]
        for key in (
            "id",
            "username",
            "email",
            "firstName",
            "lastName",
            "enabled",
        )
        if key in user
    }


def translate_admin_error(error: RuntimeError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail="Identity provider operation failed",
    )


def audit_lifecycle_operation(
    writer: AuditWriter,
    actor: dict[str, Any],
    request: Request,
    *,
    action: str,
    target_user_id: str | None,
    outcome: str,
    details: dict[str, Any] | None = None,
) -> None:
    write_lifecycle_audit(
        writer,
        actor=actor,
        action=action,
        target_user_id=target_user_id,
        outcome=outcome,
        request_id=request.state.request_id,
        details=details,
    )


@router.post("", status_code=status.HTTP_201_CREATED)
async def provision_user(
    payload: UserCreate,
    request: Request,
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
    actor: Annotated[dict[str, Any], Depends(get_current_user)],
    audit_writer: Annotated[AuditWriter, Depends(get_audit_writer)],
) -> dict[str, str]:
    try:
        existing = await admin.find_users(payload.username)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )

        await admin.create_user(
            username=payload.username,
            email=payload.email,
            first_name=payload.first_name,
            last_name=payload.last_name,
        )
    except RuntimeError as error:
        audit_lifecycle_operation(
            audit_writer,
            actor,
            request,
            action="user.provision",
            target_user_id=None,
            outcome="failure",
            details={"username": payload.username},
        )
        raise translate_admin_error(error) from error

    audit_lifecycle_operation(
        audit_writer,
        actor,
        request,
        action="user.provision",
        target_user_id=None,
        outcome="success",
        details={"username": payload.username},
    )
    return {"status": "created", "username": payload.username}


@router.get("")
async def search_users(
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
    username: Annotated[str, Query(min_length=1, max_length=100)],
) -> list[dict[str, Any]]:
    try:
        users = await admin.find_users(username)
        return [safe_user(user) for user in users]
    except RuntimeError as error:
        raise translate_admin_error(error) from error


@router.patch("/{user_id}/status")
async def update_user_status(
    user_id: str,
    payload: UserStatusUpdate,
    request: Request,
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
    actor: Annotated[dict[str, Any], Depends(get_current_user)],
    audit_writer: Annotated[AuditWriter, Depends(get_audit_writer)],
) -> dict[str, Any]:
    try:
        await admin.set_user_enabled(user_id, payload.enabled)
    except RuntimeError as error:
        audit_lifecycle_operation(
            audit_writer,
            actor,
            request,
            action="user.status.update",
            target_user_id=user_id,
            outcome="failure",
            details={"enabled": payload.enabled},
        )
        raise translate_admin_error(error) from error

    audit_lifecycle_operation(
        audit_writer,
        actor,
        request,
        action="user.status.update",
        target_user_id=user_id,
        outcome="success",
        details={"enabled": payload.enabled},
    )
    return {"user_id": user_id, "enabled": payload.enabled}


@router.get("/{user_id}/roles")
async def list_user_roles(
    user_id: str,
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
) -> list[str]:
    try:
        roles = await admin.get_user_client_roles(
            user_id,
            "identitybridge-api",
        )
        return [
            role["name"]
            for role in roles
            if isinstance(role, dict) and isinstance(role.get("name"), str)
        ]
    except RuntimeError as error:
        raise translate_admin_error(error) from error


@router.post("/{user_id}/roles", status_code=status.HTTP_204_NO_CONTENT)
async def assign_user_role(
    user_id: str,
    payload: RoleAssignment,
    request: Request,
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
    actor: Annotated[dict[str, Any], Depends(get_current_user)],
    audit_writer: Annotated[AuditWriter, Depends(get_audit_writer)],
) -> None:
    if payload.role not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Role is not an approved IdentityBridge client role",
        )

    if payload.role in PRIVILEGED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privileged roles must be granted through the JIT approval workflow",
        )

    try:
        await admin.assign_client_role(
            user_id,
            "identitybridge-api",
            payload.role,
        )
    except RuntimeError as error:
        audit_lifecycle_operation(
            audit_writer,
            actor,
            request,
            action="user.role.assign",
            target_user_id=user_id,
            outcome="failure",
            details={"role": payload.role},
        )
        raise translate_admin_error(error) from error

    audit_lifecycle_operation(
        audit_writer,
        actor,
        request,
        action="user.role.assign",
        target_user_id=user_id,
        outcome="success",
        details={"role": payload.role},
    )


@router.delete(
    "/{user_id}/roles/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_user_role(
    user_id: str,
    role_name: str,
    request: Request,
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
    actor: Annotated[dict[str, Any], Depends(get_current_user)],
    audit_writer: Annotated[AuditWriter, Depends(get_audit_writer)],
) -> None:
    if role_name not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Role is not an approved IdentityBridge client role",
        )

    if role_name in PRIVILEGED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Privileged roles must be managed through the JIT workflow",
        )

    try:
        await admin.remove_client_role(
            user_id,
            "identitybridge-api",
            role_name,
        )
    except RuntimeError as error:
        audit_lifecycle_operation(
            audit_writer,
            actor,
            request,
            action="user.role.remove",
            target_user_id=user_id,
            outcome="failure",
            details={"role": role_name},
        )
        raise translate_admin_error(error) from error

    audit_lifecycle_operation(
        audit_writer,
        actor,
        request,
        action="user.role.remove",
        target_user_id=user_id,
        outcome="success",
        details={"role": role_name},
    )
