from datetime import UTC
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from identitybridge.application.privileges import (
    create_privilege_request,
    decide_privilege_request,
)
from identitybridge.infrastructure.privilege_request_models import PrivilegeRequest


def test_create_privilege_request_creates_pending_request():
    db = MagicMock()
    db.scalar.return_value = None

    result = create_privilege_request(
        db,
        requester_sub="requester-123",
        target_user_id="target-456",
        role_name="identity-admin",
        justification="Emergency production access is required.",
        duration_minutes=60,
    )

    created = next(
        call.args[0] for call in db.add.call_args_list if isinstance(call.args[0], PrivilegeRequest)
    )
    assert result is created
    assert created.status == "pending"
    assert created.requester_sub == "requester-123"
    assert created.target_user_id == "target-456"
    assert created.role_name == "identity-admin"
    assert created.requested_duration_minutes == 60
    db.execute.assert_called_once()
    assert db.add.call_count == 2
    audit_event = next(
        call.args[0] for call in db.add.call_args_list if call.args[0] is not created
    )
    assert audit_event.action == "privilege.request"
    assert audit_event.outcome == "success"
    assert audit_event.details == {
        "role": "identity-admin",
        "status": "pending",
        "duration_minutes": 60,
    }
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(created)


def test_create_privilege_request_rejects_duplicate():
    db = MagicMock()
    db.scalar.return_value = uuid4()

    with pytest.raises(ValueError, match="outstanding request already exists"):
        create_privilege_request(
            db,
            requester_sub="requester-123",
            target_user_id="target-456",
            role_name="identity-admin",
            justification="Emergency production access is required.",
            duration_minutes=60,
        )

    db.add.assert_not_called()
    db.commit.assert_not_called()
    db.rollback.assert_called_once()


def test_create_privilege_request_rolls_back_on_database_error():
    db = MagicMock()
    db.execute.side_effect = RuntimeError("database unavailable")

    with pytest.raises(RuntimeError, match="database unavailable"):
        create_privilege_request(
            db,
            requester_sub="requester-123",
            target_user_id="target-456",
            role_name="identity-admin",
            justification="Emergency production access is required.",
            duration_minutes=60,
        )

    db.rollback.assert_called_once()


def test_approver_can_approve_pending_request():
    request = MagicMock()
    request.status = "pending"
    request.requester_sub = "requester-123"

    db = MagicMock()
    db.scalar.return_value = request

    result = decide_privilege_request(
        db,
        request_id=uuid4(),
        approver_sub="approver-789",
        approve=True,
    )

    assert result is request
    assert request.status == "approved"
    assert request.approver_sub == "approver-789"
    assert request.approved_at is not None
    assert request.approved_at.tzinfo == UTC
    db.commit.assert_called_once()
    db.refresh.assert_called_once_with(request)


def test_approver_can_reject_pending_request():
    request = MagicMock()
    request.status = "pending"
    request.requester_sub = "requester-123"

    db = MagicMock()
    db.scalar.return_value = request

    result = decide_privilege_request(
        db,
        request_id=uuid4(),
        approver_sub="approver-789",
        approve=False,
    )

    assert result is request
    assert request.status == "rejected"
    assert request.approver_sub == "approver-789"
    db.commit.assert_called_once()


def test_requester_cannot_approve_own_request():
    request = MagicMock()
    request.status = "pending"
    request.requester_sub = "same-user"

    db = MagicMock()
    db.scalar.return_value = request

    with pytest.raises(PermissionError, match="cannot approve their own requests"):
        decide_privilege_request(
            db,
            request_id=uuid4(),
            approver_sub="same-user",
            approve=True,
        )

    db.commit.assert_not_called()
    db.rollback.assert_called_once()


def test_non_pending_request_cannot_be_decided():
    request = MagicMock()
    request.status = "approved"
    request.requester_sub = "requester-123"

    db = MagicMock()
    db.scalar.return_value = request

    with pytest.raises(ValueError, match="Only pending requests can be decided"):
        decide_privilege_request(
            db,
            request_id=uuid4(),
            approver_sub="approver-789",
            approve=False,
        )

    db.commit.assert_not_called()
    db.rollback.assert_called_once()


def test_missing_request_cannot_be_decided():
    db = MagicMock()
    db.scalar.return_value = None

    with pytest.raises(LookupError, match="Privilege request was not found"):
        decide_privilege_request(
            db,
            request_id=uuid4(),
            approver_sub="approver-789",
            approve=True,
        )

    db.commit.assert_not_called()
    db.rollback.assert_called_once()


@pytest.mark.parametrize("operation", ["create", "approve", "reject"])
def test_audit_insertion_failure_rolls_back_transaction(monkeypatch, operation):
    from identitybridge.application import privileges as privilege_service

    db = MagicMock()

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit insertion failed")

    monkeypatch.setattr(privilege_service, "add_audit_event", fail_audit)

    if operation == "create":
        db.scalar.return_value = None

        def perform_operation():
            return create_privilege_request(
                db,
                requester_sub="requester-123",
                target_user_id="requester-123",
                role_name="identity-admin",
                justification="Emergency production access is required.",
                duration_minutes=60,
            )
    else:
        privilege_request = MagicMock()
        privilege_request.status = "pending"
        privilege_request.requester_sub = "requester-123"
        privilege_request.target_user_id = "requester-123"
        privilege_request.role_name = "identity-admin"
        privilege_request.requested_duration_minutes = 60
        db.scalar.return_value = privilege_request

        def perform_operation():
            return decide_privilege_request(
                db,
                request_id=uuid4(),
                approver_sub="approver-789",
                approve=operation == "approve",
                decision_comment="Reviewed security justification.",
            )

    with pytest.raises(RuntimeError, match="audit insertion failed"):
        perform_operation()

    db.rollback.assert_called_once()
    db.commit.assert_not_called()
    db.refresh.assert_not_called()
