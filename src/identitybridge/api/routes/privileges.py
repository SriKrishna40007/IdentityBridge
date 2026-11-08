from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from identitybridge.api.schemas.privileges import (
    PrivilegeDecision,
    PrivilegeRequestCreate,
    PrivilegeRequestRead,
)
from identitybridge.application.audit import (
    AuditWriter,
    get_audit_writer,
    write_lifecycle_audit,
)
from identitybridge.application.privilege_grants import grant_approved_privilege
from identitybridge.application.privileges import (
    create_privilege_request,
    decide_privilege_request,
)
from identitybridge.config.settings import Settings
from identitybridge.infrastructure.database import get_db
from identitybridge.infrastructure.keycloak.admin_client import (
    KeycloakAdminClient,
)
from identitybridge.infrastructure.privilege_request_models import (
    PrivilegeRequest,
)
from identitybridge.security.authorization import get_current_user, require_roles

router = APIRouter(prefix="/api/v1/privileges", tags=["Just-in-time privileged access"])


def get_admin_client(request: Request) -> KeycloakAdminClient:
    return request.app.state.keycloak_admin


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


def audit_privilege_action(
    writer: AuditWriter,
    actor: dict,
    request: Request,
    *,
    action: str,
    target_user_id: str,
    outcome: str,
    details: dict,
) -> None:
    write_lifecycle_audit(
        writer,
        actor=actor,
        action=action,
        target_user_id=target_user_id,
        outcome=outcome,
        request_id=getattr(request.state, "request_id", None),
        details=details,
    )


@router.post(
    "/requests",
    response_model=PrivilegeRequestRead,
    status_code=status.HTTP_201_CREATED,
)
def submit_privilege_request(
    payload: PrivilegeRequestCreate,
    request: Request,
    actor: Annotated[dict, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> PrivilegeRequest:
    requester_sub = actor["sub"]

    if payload.target_user_id != requester_sub:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Users may request privileged access only for themselves",
        )

    try:
        item = create_privilege_request(
            db,
            requester_sub=requester_sub,
            target_user_id=payload.target_user_id,
            role_name=payload.role,
            justification=payload.justification,
            duration_minutes=payload.duration_minutes,
            actor_username=actor.get("preferred_username"),
            request_id=getattr(request.state, "request_id", None),
        )
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        ) from error

    return item


@router.get("/requests", response_model=list[PrivilegeRequestRead])
def list_own_privilege_requests(
    actor: Annotated[dict, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> list[PrivilegeRequest]:
    return list(
        db.scalars(
            select(PrivilegeRequest)
            .where(PrivilegeRequest.requester_sub == actor["sub"])
            .order_by(PrivilegeRequest.requested_at.desc())
        ).all()
    )


@router.get(
    "/pending",
    response_model=list[PrivilegeRequestRead],
    dependencies=[Depends(require_roles("identity-admin"))],
)
def list_pending_privilege_requests(
    db: Annotated[Session, Depends(get_db)],
) -> list[PrivilegeRequest]:
    return list(
        db.scalars(
            select(PrivilegeRequest)
            .where(PrivilegeRequest.status == "pending")
            .order_by(PrivilegeRequest.requested_at.asc())
        ).all()
    )


@router.post(
    "/{request_id}/approve",
    response_model=PrivilegeRequestRead,
    dependencies=[Depends(require_roles("identity-admin"))],
)
async def approve_privilege_request(
    request_id: UUID,
    payload: PrivilegeDecision,
    request: Request,
    actor: Annotated[dict, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[KeycloakAdminClient, Depends(get_admin_client)],
    settings: Annotated[Settings, Depends(get_app_settings)],
    audit_writer: Annotated[AuditWriter, Depends(get_audit_writer)],
) -> PrivilegeRequest:
    try:
        item = decide_privilege_request(
            db,
            request_id=request_id,
            approver_sub=actor["sub"],
            approve=True,
            decision_comment=payload.comment,
            actor_username=actor.get("preferred_username"),
            audit_request_id=getattr(request.state, "request_id", None),
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error

    item = await grant_approved_privilege(
        db,
        admin,
        request_id=request_id,
        client_id=settings.oidc_client_id,
        exclusive_role_writer=False,
    )

    outcome = "success" if item.status == "active" else "failure"

    audit_privilege_action(
        audit_writer,
        actor,
        request,
        action="privilege.grant",
        target_user_id=item.target_user_id,
        outcome=outcome,
        details={
            "role": item.role_name,
            "status": item.status,
            "duration_minutes": item.requested_duration_minutes,
        },
    )
    return item


@router.post(
    "/{request_id}/reject",
    response_model=PrivilegeRequestRead,
    dependencies=[Depends(require_roles("identity-admin"))],
)
def reject_privilege_request(
    request_id: UUID,
    payload: PrivilegeDecision,
    request: Request,
    actor: Annotated[dict, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> PrivilegeRequest:
    try:
        item = decide_privilege_request(
            db,
            request_id=request_id,
            approver_sub=actor["sub"],
            approve=False,
            decision_comment=payload.comment,
            actor_username=actor.get("preferred_username"),
            audit_request_id=getattr(request.state, "request_id", None),
        )
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error

    return item
