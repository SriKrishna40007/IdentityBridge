from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from identitybridge.application import privilege_lifecycle as lifecycle
from identitybridge.application.privilege_lifecycle import (
    activate_privilege_grant,
    claim_expired_privileges,
    complete_privilege_revocation,
    prepare_privilege_grant,
    prepare_privilege_retry,
    prepare_privilege_revocation,
    record_ambiguous_grant,
    record_preexisting_role,
)
from identitybridge.infrastructure.privilege_request_models import PrivilegeRequest


def make_request(status="approved"):
    return PrivilegeRequest(
        id=uuid4(),
        requester_sub="requester-001",
        target_user_id="target-001",
        role_name="security-analyst",
        justification="Investigate an approved security incident.",
        requested_duration_minutes=60,
        status=status,
        role_preexisting=None,
        grant_applied=False,
        retry_count=0,
    )


def mock_db(item):
    db = MagicMock()
    db.scalar.return_value = item
    return db


def capture_lifecycle_audits(monkeypatch):
    events = []

    def record(_db, item, *, action, outcome="success"):
        events.append(
            {
                "request_id": item.id,
                "status": item.status,
                "action": action,
                "outcome": outcome,
            }
        )

    monkeypatch.setattr(lifecycle, "_audit_transition", record)
    return events


def test_prepare_grant_persists_pending_state():
    item = make_request()
    db = mock_db(item)

    result = prepare_privilege_grant(db, item.id)

    assert result.status == "grant_pending"
    assert result.role_preexisting is None
    assert result.grant_applied is False
    db.commit.assert_called_once()


def test_preexisting_role_is_preserved_after_activation():
    item = make_request("grant_pending")
    db = mock_db(item)

    record_preexisting_role(db, item.id, role_exists=True)
    result = activate_privilege_grant(db, item.id, granted_by_jit=False)

    assert result.status == "active"
    assert result.role_preexisting is True
    assert result.grant_applied is False
    assert result.expires_at is not None
    assert result.expires_at > result.activated_at


def test_new_jit_role_is_recorded_as_owned_by_jit():
    item = make_request("grant_pending")
    db = mock_db(item)

    record_preexisting_role(db, item.id, role_exists=False)
    result = activate_privilege_grant(db, item.id, granted_by_jit=True)

    assert result.status == "active"
    assert result.role_preexisting is False
    assert result.grant_applied is True


def test_preexisting_role_cannot_be_marked_as_jit_grant():
    item = make_request("grant_pending")
    db = mock_db(item)

    record_preexisting_role(db, item.id, role_exists=True)

    with pytest.raises(ValueError):
        activate_privilege_grant(db, item.id, granted_by_jit=True)

    assert item.status == "grant_pending"


def test_ambiguous_grant_requires_manual_reconciliation():
    item = make_request("grant_pending")
    db = mock_db(item)

    result = record_ambiguous_grant(db, item.id)

    assert result.status == "grant_failed"
    assert result.retry_count == 1
    assert result.next_retry_at is None
    assert "manual ownership reconciliation" in result.last_error


def test_only_approved_requests_can_be_prepared():
    item = make_request("pending")
    db = mock_db(item)

    with pytest.raises(ValueError):
        prepare_privilege_grant(db, item.id)

    db.rollback.assert_called_once()


def test_expired_jit_owned_role_moves_to_revoke_pending(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("active")
    item.role_preexisting = False
    item.grant_applied = True
    item.expires_at = now - timedelta(minutes=1)
    db = mock_db(item)
    events = capture_lifecycle_audits(monkeypatch)

    result = prepare_privilege_revocation(db, item.id, now=now)

    assert result.status == "revoke_pending"
    assert result.revocation_requested_at == now
    assert [event["action"] for event in events] == ["privilege.revoke.prepare"]
    db.commit.assert_called_once()


def test_expired_preexisting_role_is_not_removed_and_is_audited(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("active")
    item.role_preexisting = True
    item.grant_applied = False
    item.expires_at = now - timedelta(minutes=1)
    events = capture_lifecycle_audits(monkeypatch)

    result = prepare_privilege_revocation(mock_db(item), item.id, now=now)

    assert result.status == "expired"
    assert result.grant_applied is False
    assert [event["action"] for event in events] == ["privilege.expire"]


def test_unexpired_request_cannot_be_revoked():
    now = datetime.now(UTC)
    item = make_request("active")
    item.role_preexisting = False
    item.grant_applied = True
    item.expires_at = now + timedelta(minutes=10)
    db = mock_db(item)

    with pytest.raises(ValueError, match="has not expired"):
        prepare_privilege_revocation(db, item.id, now=now)

    db.rollback.assert_called_once()


def test_unknown_role_ownership_blocks_revocation():
    now = datetime.now(UTC)
    item = make_request("active")
    item.role_preexisting = None
    item.grant_applied = False
    item.expires_at = now - timedelta(minutes=1)
    db = mock_db(item)

    with pytest.raises(ValueError, match="ownership is unknown"):
        prepare_privilege_revocation(db, item.id, now=now)

    db.rollback.assert_called_once()


def test_verified_revocation_marks_request_expired_and_audits(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("revoke_pending")
    item.role_preexisting = False
    item.grant_applied = True
    db = mock_db(item)
    events = capture_lifecycle_audits(monkeypatch)

    result = complete_privilege_revocation(db, item.id, role_absent=True, now=now)

    assert result.status == "expired"
    assert result.revoked_at == now
    assert result.last_error is None
    assert [(e["action"], e["outcome"]) for e in events] == [
        ("privilege.revoke.complete", "success")
    ]


def test_unverified_revocation_schedules_retry_and_audits_failure(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("revoke_pending")
    item.role_preexisting = False
    item.grant_applied = True
    db = mock_db(item)
    events = capture_lifecycle_audits(monkeypatch)

    result = complete_privilege_revocation(db, item.id, role_absent=False, now=now)

    assert result.status == "revoke_failed"
    assert result.retry_count == 1
    assert result.next_retry_at == now + timedelta(minutes=2)
    assert result.last_error is not None
    assert [(e["action"], e["outcome"]) for e in events] == [
        ("privilege.revoke.retry_scheduled", "failure")
    ]


def test_due_retry_claim_is_audited(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("revoke_failed")
    item.role_preexisting = False
    item.grant_applied = True
    item.next_retry_at = now - timedelta(seconds=1)
    events = capture_lifecycle_audits(monkeypatch)

    result = prepare_privilege_retry(mock_db(item), item.id, now=now)

    assert result.status == "revoke_pending"
    assert result.next_retry_at is None
    assert [e["action"] for e in events] == ["privilege.revoke.retry_claim"]


def test_retry_not_due_is_rejected():
    now = datetime.now(UTC)
    item = make_request("revoke_failed")
    item.role_preexisting = False
    item.grant_applied = True
    item.next_retry_at = now + timedelta(minutes=5)
    db = mock_db(item)

    with pytest.raises(ValueError, match="not due"):
        prepare_privilege_retry(db, item.id, now=now)

    db.rollback.assert_called_once()


def test_audit_failure_rolls_back_revocation_transition(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("active")
    item.role_preexisting = False
    item.grant_applied = True
    item.expires_at = now - timedelta(minutes=1)
    db = mock_db(item)

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit persistence failed")

    monkeypatch.setattr(lifecycle, "_audit_transition", fail_audit)

    with pytest.raises(RuntimeError, match="audit persistence failed"):
        prepare_privilege_revocation(db, item.id, now=now)

    db.rollback.assert_called_once()
    db.commit.assert_not_called()


def test_batch_claim_audits_each_transition(monkeypatch):
    now = datetime.now(UTC)

    owned_active = make_request("active")
    owned_active.role_preexisting = False
    owned_active.grant_applied = True
    owned_active.expires_at = now - timedelta(minutes=3)

    preexisting_active = make_request("active")
    preexisting_active.role_preexisting = True
    preexisting_active.grant_applied = False
    preexisting_active.expires_at = now - timedelta(minutes=2)

    failed_retry = make_request("revoke_failed")
    failed_retry.role_preexisting = False
    failed_retry.grant_applied = True
    failed_retry.retry_count = 1
    failed_retry.next_retry_at = now - timedelta(minutes=1)

    uncertain = make_request("active")
    uncertain.role_preexisting = None
    uncertain.grant_applied = False
    uncertain.expires_at = now

    db = MagicMock()
    db.scalars.return_value.all.return_value = [
        owned_active,
        preexisting_active,
        failed_retry,
        uncertain,
    ]
    events = capture_lifecycle_audits(monkeypatch)

    claimed = claim_expired_privileges(db, now=now, batch_size=10)

    assert [entry[1] for entry in claimed] == [
        "revoke_pending",
        "expired",
        "revoke_pending",
        "manual",
    ]
    assert [event["action"] for event in events] == [
        "privilege.revoke.prepare",
        "privilege.expire",
        "privilege.revoke.retry_claim",
        "privilege.expiry.manual_reconciliation",
    ]
    assert events[-1]["outcome"] == "failure"
    assert len(events) == len(claimed)
    db.commit.assert_called_once()


def test_batch_audit_failure_rolls_back_all_claims(monkeypatch):
    now = datetime.now(UTC)
    item = make_request("active")
    item.role_preexisting = False
    item.grant_applied = True
    item.expires_at = now - timedelta(minutes=1)

    db = MagicMock()
    db.scalars.return_value.all.return_value = [item]

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit persistence failed")

    monkeypatch.setattr(lifecycle, "_audit_transition", fail_audit)

    with pytest.raises(RuntimeError, match="audit persistence failed"):
        claim_expired_privileges(db, now=now)

    db.rollback.assert_called_once()
    db.commit.assert_not_called()
