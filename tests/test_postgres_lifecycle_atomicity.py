import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from identitybridge.application.privilege_lifecycle import (
    prepare_privilege_revocation,
)
from identitybridge.infrastructure.audit_models import AuditEvent
from identitybridge.infrastructure.database import SessionLocal
from identitybridge.infrastructure.privilege_request_models import PrivilegeRequest

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_POSTGRES_INTEGRATION") != "1",
    reason="Set RUN_POSTGRES_INTEGRATION=1 to run against PostgreSQL",
)


def create_expired_request(db, *, target_user_id):
    item = PrivilegeRequest(
        id=uuid4(),
        requester_sub="postgres-integration-requester",
        target_user_id=target_user_id,
        role_name="security-analyst",
        justification="PostgreSQL lifecycle atomicity integration test.",
        requested_duration_minutes=60,
        status="active",
        role_preexisting=False,
        grant_applied=True,
        retry_count=0,
        expires_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def test_postgres_lifecycle_transition_and_audit_commit_together():
    target = f"postgres-integration-{uuid4()}"
    db = SessionLocal()
    request_id = None

    try:
        item = create_expired_request(db, target_user_id=target)
        request_id = item.id

        result = prepare_privilege_revocation(db, item.id)

        assert result.status == "revoke_pending"

        persisted_request = db.get(PrivilegeRequest, item.id)
        assert persisted_request.status == "revoke_pending"

        audit = db.scalar(
            select(AuditEvent).where(
                AuditEvent.request_id == str(item.id),
                AuditEvent.action == "privilege.revoke.prepare",
            )
        )
        assert audit is not None
        assert audit.outcome == "success"
        assert audit.details["status"] == "revoke_pending"

    finally:
        if request_id is not None:
            db.query(AuditEvent).filter(
                AuditEvent.request_id == str(request_id)
            ).delete(synchronize_session=False)
            db.query(PrivilegeRequest).filter(
                PrivilegeRequest.id == request_id
            ).delete(synchronize_session=False)
            db.commit()
        db.close()


def test_postgres_lifecycle_state_rolls_back_if_audit_insert_fails(monkeypatch):
    target = f"postgres-integration-{uuid4()}"
    db = SessionLocal()
    request_id = None

    def fail_audit(*args, **kwargs):
        raise RuntimeError("Injected PostgreSQL audit failure")

    try:
        item = create_expired_request(db, target_user_id=target)
        request_id = item.id

        monkeypatch.setattr(
            "identitybridge.application.privilege_lifecycle.add_audit_event",
            fail_audit,
        )

        with pytest.raises(RuntimeError, match="Injected PostgreSQL audit failure"):
            prepare_privilege_revocation(db, item.id)

        db.expire_all()
        persisted_request = db.get(PrivilegeRequest, item.id)

        assert persisted_request.status == "active"

        audit = db.scalar(
            select(AuditEvent).where(
                AuditEvent.request_id == str(item.id),
                AuditEvent.action == "privilege.revoke.prepare",
            )
        )
        assert audit is None

    finally:
        if request_id is not None:
            db.query(AuditEvent).filter(
                AuditEvent.request_id == str(request_id)
            ).delete(synchronize_session=False)
            db.query(PrivilegeRequest).filter(
                PrivilegeRequest.id == request_id
            ).delete(synchronize_session=False)
            db.commit()
        db.close()
