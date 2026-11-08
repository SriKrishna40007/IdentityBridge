from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from identitybridge.infrastructure.audit_service import add_audit_event
from identitybridge.infrastructure.privilege_request_models import (
    PrivilegeRequest,
)

SYSTEM_ACTOR_SUB = "system:identitybridge-jit"
SYSTEM_ACTOR_USERNAME = "IdentityBridge JIT Service"

REVOCATION_CLAIM_LEASE = timedelta(minutes=5)


def _audit_transition(
    db: Session, item: PrivilegeRequest, *, action: str, outcome: str = "success"
) -> None:
    add_audit_event(
        db,
        actor_sub=SYSTEM_ACTOR_SUB,
        actor_username=SYSTEM_ACTOR_USERNAME,
        action=action,
        target_user_id=item.target_user_id,
        outcome=outcome,
        request_id=str(item.id),
        details={
            "role": item.role_name,
            "status": item.status,
            "duration_minutes": item.requested_duration_minutes,
        },
    )


def prepare_privilege_grant(
    db: Session,
    request_id: UUID,
) -> PrivilegeRequest:
    """Persist grant intent before calling the identity provider."""
    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "approved":
            raise ValueError("Only approved requests can be activated")

        item.status = "grant_pending"
        item.role_preexisting = None
        item.grant_applied = False
        item.last_error = None
        item.next_retry_at = None

        _audit_transition(db, item, action="privilege.grant.prepare")
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def record_preexisting_role(
    db: Session,
    request_id: UUID,
    *,
    role_exists: bool,
) -> PrivilegeRequest:
    """Persist the role observation before attempting a grant."""
    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "grant_pending":
            raise ValueError("Request is not awaiting a role grant")

        if item.role_preexisting is not None:
            raise ValueError("Initial role ownership has already been recorded")

        item.role_preexisting = role_exists

        _audit_transition(db, item, action="privilege.grant.ownership_recorded")
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def activate_privilege_grant(
    db: Session,
    request_id: UUID,
    *,
    granted_by_jit: bool,
) -> PrivilegeRequest:
    """Record verified activation and calculate its expiry."""
    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "grant_pending":
            raise ValueError("Request is not awaiting activation")

        if item.role_preexisting is None:
            raise ValueError("Initial role ownership has not been established")

        if granted_by_jit and item.role_preexisting:
            raise ValueError("A pre-existing role cannot be recorded as a JIT grant")

        now = datetime.now(UTC)
        item.status = "active"
        item.grant_applied = granted_by_jit
        item.activated_at = now
        item.expires_at = now + timedelta(minutes=item.requested_duration_minutes)
        item.last_error = None
        item.next_retry_at = None

        _audit_transition(db, item, action="privilege.grant.activate")
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def record_ambiguous_grant(
    db: Session,
    request_id: UUID,
) -> PrivilegeRequest:
    """Stop automatic processing when grant ownership cannot be proven."""
    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "grant_pending":
            raise ValueError("Request is not awaiting grant reconciliation")

        item.status = "grant_failed"
        item.retry_count += 1
        item.next_retry_at = None
        item.last_error = "Ambiguous role assignment; manual ownership reconciliation required"

        _audit_transition(
            db,
            item,
            action="privilege.grant.manual_reconciliation",
            outcome="failure",
        )
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def prepare_privilege_revocation(
    db: Session,
    request_id: UUID,
    *,
    now: datetime | None = None,
) -> PrivilegeRequest:
    """Claim an expired request for revocation or mark it expired safely."""
    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None:
        raise ValueError("Revocation timestamp must be timezone-aware")

    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "active":
            raise ValueError("Only active requests can expire")

        if item.expires_at is None or item.expires_at > current_time:
            raise ValueError("Privilege request has not expired")

        if item.role_preexisting is None:
            raise ValueError("Role ownership is unknown; manual reconciliation required")

        if item.role_preexisting and item.grant_applied:
            raise ValueError("Role ownership state is contradictory")

        item.next_retry_at = None

        if item.grant_applied and not item.role_preexisting:
            item.status = "revoke_pending"
            item.revocation_requested_at = current_time
            audit_action = "privilege.revoke.prepare"
        else:
            item.status = "expired"
            item.last_error = None
            audit_action = "privilege.expire"

        _audit_transition(db, item, action=audit_action)
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def complete_privilege_revocation(
    db: Session,
    request_id: UUID,
    *,
    role_absent: bool,
    now: datetime | None = None,
) -> PrivilegeRequest:
    """Record verified removal or schedule a bounded retry."""
    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None:
        raise ValueError("Revocation timestamp must be timezone-aware")

    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "revoke_pending":
            raise ValueError("Request is not awaiting revocation")

        if not item.grant_applied or item.role_preexisting is not False:
            raise ValueError("Request does not have verified JIT role ownership")

        if role_absent:
            item.status = "expired"
            item.revoked_at = current_time
            item.next_retry_at = None
            item.last_error = None
        else:
            item.status = "revoke_failed"
            item.retry_count += 1
            retry_minutes = min(2 ** min(item.retry_count, 6), 60)
            item.next_retry_at = current_time + timedelta(minutes=retry_minutes)
            item.last_error = "Role removal not verified; retry scheduled"

        _audit_transition(
            db,
            item,
            action=(
                "privilege.revoke.complete" if role_absent else "privilege.revoke.retry_scheduled"
            ),
            outcome="success" if role_absent else "failure",
        )
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def prepare_privilege_retry(
    db: Session,
    request_id: UUID,
    *,
    now: datetime | None = None,
) -> PrivilegeRequest:
    """Claim a due revocation retry without losing ownership information."""
    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None:
        raise ValueError("Retry timestamp must be timezone-aware")

    try:
        item = db.scalar(
            select(PrivilegeRequest).where(PrivilegeRequest.id == request_id).with_for_update()
        )

        if item is None:
            raise LookupError("Privilege request was not found")

        if item.status != "revoke_failed":
            raise ValueError("Request is not awaiting a revocation retry")

        if item.next_retry_at is None or item.next_retry_at > current_time:
            raise ValueError("Revocation retry is not due")

        if item.role_preexisting is not False or not item.grant_applied:
            raise ValueError("Verified JIT ownership is required for retry")

        item.status = "revoke_pending"
        item.revocation_requested_at = current_time
        item.next_retry_at = None

        _audit_transition(
            db,
            item,
            action="privilege.revoke.retry_claim",
        )
        db.commit()
        db.refresh(item)
        return item

    except Exception:
        db.rollback()
        raise


def claim_expired_privileges(
    db: Session,
    *,
    now: datetime | None = None,
    batch_size: int = 50,
) -> list[tuple[UUID, str, str, str]]:
    """Atomically claim expired privileges and due revocation retries.

    Returns tuples of (request_id, action, target_user_id, role_name).

    Actions:
      - revoke_pending: safe to process through Keycloak.
      - expired: no JIT-owned role needs removal.
      - manual: ownership is uncertain and requires reconciliation.
    """
    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None:
        raise ValueError("Claim timestamp must be timezone-aware")

    if not 1 <= batch_size <= 500:
        raise ValueError("Batch size must be between 1 and 500")

    try:
        candidates = db.scalars(
            select(PrivilegeRequest)
            .where(
                or_(
                    and_(
                        PrivilegeRequest.status == "active",
                        PrivilegeRequest.expires_at <= current_time,
                    ),
                    and_(
                        PrivilegeRequest.status == "revoke_failed",
                        PrivilegeRequest.next_retry_at <= current_time,
                    ),
                    and_(
                        PrivilegeRequest.status == "revoke_pending",
                        PrivilegeRequest.revocation_requested_at
                        <= current_time - REVOCATION_CLAIM_LEASE,
                    ),
                )
            )
            .order_by(PrivilegeRequest.expires_at.asc())
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        ).all()

        claimed: list[tuple[UUID, str, str, str]] = []

        for item in candidates:
            previous_status = item.status
            action = "manual"

            ownership_verified = item.role_preexisting is False and item.grant_applied is True

            if item.status == "active":
                if ownership_verified:
                    item.status = "revoke_pending"
                    item.revocation_requested_at = current_time
                    item.next_retry_at = None
                    action = "revoke_pending"

                elif item.role_preexisting is True and not item.grant_applied:
                    item.status = "expired"
                    item.last_error = None
                    item.next_retry_at = None
                    action = "expired"

                else:
                    item.status = "revoke_failed"
                    item.next_retry_at = None
                    item.last_error = "Role ownership is uncertain; manual reconciliation required"

            elif item.status in {"revoke_failed", "revoke_pending"}:
                if ownership_verified:
                    item.status = "revoke_pending"
                    item.revocation_requested_at = current_time
                    item.next_retry_at = None
                    action = "revoke_pending"

                else:
                    item.status = "revoke_failed"
                    item.next_retry_at = None
                    item.last_error = "Role ownership is uncertain; manual reconciliation required"

            claimed.append(
                (
                    item.id,
                    action,
                    item.target_user_id,
                    item.role_name,
                )
            )

            if action == "revoke_pending":
                audit_action = (
                    "privilege.revoke.retry_claim"
                    if previous_status in {"revoke_failed", "revoke_pending"}
                    else "privilege.revoke.prepare"
                )
                _audit_transition(db, item, action=audit_action)
            elif action == "expired":
                _audit_transition(
                    db,
                    item,
                    action="privilege.expire",
                )
            else:
                _audit_transition(
                    db,
                    item,
                    action="privilege.expiry.manual_reconciliation",
                    outcome="failure",
                )

        # Persist all claims in one transaction. Other workers skip
        # rows locked by this transaction.
        db.commit()
        return claimed

    except Exception:
        db.rollback()
        raise
