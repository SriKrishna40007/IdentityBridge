from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from identitybridge.infrastructure.audit_service import add_audit_event
from identitybridge.infrastructure.privilege_request_models import (
    PrivilegeRequest,
)

OUTSTANDING_STATUSES = (
    "pending",
    "approved",
    "grant_pending",
    "grant_failed",
    "active",
    "revoke_pending",
    "revoke_failed",
)


def create_privilege_request(
    db: Session,
    *,
    requester_sub: str,
    target_user_id: str,
    role_name: str,
    justification: str,
    duration_minutes: int,
    actor_username: str | None = None,
    request_id: str | None = None,
) -> PrivilegeRequest:
    """Create a request and its audit event in one transaction."""
    lock_key = f"jit:{target_user_id}:{role_name}"

    try:
        db.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {"lock_key": lock_key},
        )

        existing = db.scalar(
            select(PrivilegeRequest.id)
            .where(
                PrivilegeRequest.target_user_id == target_user_id,
                PrivilegeRequest.role_name == role_name,
                PrivilegeRequest.status.in_(OUTSTANDING_STATUSES),
            )
            .limit(1)
        )

        if existing is not None:
            raise ValueError("An outstanding request already exists for this user and role")

        privilege_request = PrivilegeRequest(
            requester_sub=requester_sub,
            target_user_id=target_user_id,
            role_name=role_name,
            justification=justification,
            requested_duration_minutes=duration_minutes,
            status="pending",
        )

        db.add(privilege_request)

        add_audit_event(
            db,
            actor_sub=requester_sub,
            actor_username=actor_username,
            action="privilege.request",
            target_user_id=target_user_id,
            outcome="success",
            request_id=request_id,
            details={
                "role": role_name,
                "status": "pending",
                "duration_minutes": duration_minutes,
            },
        )

        db.commit()
        db.refresh(privilege_request)
        return privilege_request

    except Exception:
        db.rollback()
        raise


def decide_privilege_request(
    db: Session,
    *,
    request_id: UUID,
    approver_sub: str,
    approve: bool,
    decision_comment: str | None = None,
    actor_username: str | None = None,
    audit_request_id: str | None = None,
) -> PrivilegeRequest:
    """Decide a pending request and audit the decision atomically.

    The decision comment is persisted for both approval and rejection.
    Self-approval is prohibited.
    """
    try:
        privilege_request = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if privilege_request is None:
            raise LookupError("Privilege request was not found")

        if privilege_request.status != "pending":
            raise ValueError("Only pending requests can be decided")

        if privilege_request.requester_sub == approver_sub:
            raise PermissionError("Requesters cannot approve their own requests")

        privilege_request.approver_sub = approver_sub
        privilege_request.decision_comment = decision_comment

        if approve:
            privilege_request.status = "approved"
            privilege_request.approved_at = datetime.now(UTC)
            action = "privilege.approve"
        else:
            privilege_request.status = "rejected"
            action = "privilege.reject"

        add_audit_event(
            db,
            actor_sub=approver_sub,
            actor_username=actor_username,
            action=action,
            target_user_id=privilege_request.target_user_id,
            outcome="success",
            request_id=audit_request_id,
            details={
                "role": privilege_request.role_name,
                "status": privilege_request.status,
                "duration_minutes": (privilege_request.requested_duration_minutes),
            },
        )

        db.commit()
        db.refresh(privilege_request)
        return privilege_request

    except Exception:
        db.rollback()
        raise
