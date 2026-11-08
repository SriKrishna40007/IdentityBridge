import pytest

from identitybridge.infrastructure import audit_service


class FakeSession:
    def __init__(self, fail_commit=False):
        self.added = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.fail_commit = fail_commit

    def add(self, event):
        self.added.append(event)

    def commit(self):
        if self.fail_commit:
            raise RuntimeError("Database commit failed")
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_record_audit_event_commits_and_closes_session(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(audit_service, "SessionLocal", lambda: session)

    audit_service.record_audit_event(
        actor_sub="admin-123",
        actor_username="admin",
        action="user.provision",
        target_user_id="user-456",
        outcome="success",
        request_id="request-789",
        details={"username": "new-user"},
    )

    assert len(session.added) == 1

    event = session.added[0]
    assert event.actor_sub == "admin-123"
    assert event.actor_username == "admin"
    assert event.action == "user.provision"
    assert event.target_user_id == "user-456"
    assert event.outcome == "success"
    assert event.request_id == "request-789"
    assert event.details == {"username": "new-user"}

    assert session.committed
    assert not session.rolled_back
    assert session.closed


def test_record_audit_event_filters_sensitive_metadata(monkeypatch):
    session = FakeSession()
    monkeypatch.setattr(audit_service, "SessionLocal", lambda: session)

    audit_service.record_audit_event(
        actor_sub="admin-123",
        actor_username="admin",
        action="user.role.assign",
        target_user_id="user-456",
        outcome="success",
        details={
            "role": "auditor",
            "password": "must-not-be-stored",
            "access_token": "must-not-be-stored",
            "refresh_token": "must-not-be-stored",
            "request_body": {"secret": "hidden"},
        },
    )

    assert session.added[0].details == {"role": "auditor"}


def test_record_audit_event_rolls_back_and_closes_on_failure(monkeypatch):
    session = FakeSession(fail_commit=True)
    monkeypatch.setattr(audit_service, "SessionLocal", lambda: session)

    with pytest.raises(RuntimeError, match="Database commit failed"):
        audit_service.record_audit_event(
            actor_sub="admin-123",
            actor_username="admin",
            action="user.provision",
            target_user_id="user-456",
            outcome="success",
        )

    assert session.rolled_back
    assert session.closed
    assert not session.committed


@pytest.mark.parametrize("outcome", ["pending", "unknown", ""])
def test_record_audit_event_rejects_invalid_outcome(outcome):
    with pytest.raises(ValueError, match="Invalid audit outcome"):
        audit_service.record_audit_event(
            actor_sub="admin-123",
            actor_username="admin",
            action="user.provision",
            target_user_id="user-456",
            outcome=outcome,
        )


def test_record_audit_event_rejects_missing_actor():
    with pytest.raises(ValueError, match="Audit actor subject is required"):
        audit_service.record_audit_event(
            actor_sub="",
            actor_username="admin",
            action="user.provision",
            target_user_id="user-456",
            outcome="success",
        )


def test_add_audit_event_uses_caller_session_without_committing():
    session = FakeSession()

    event = audit_service.add_audit_event(
        session,
        actor_sub="admin-123",
        actor_username="admin",
        action="privilege.approve",
        target_user_id="user-456",
        outcome="success",
        details={"role": "auditor", "password": "must-not-be-stored"},
    )

    assert len(session.added) == 1
    assert session.added[0] is event
    assert event.details == {"role": "auditor"}
    assert not session.committed
    assert not session.rolled_back
    assert not session.closed


def test_add_audit_event_rejects_invalid_actor():
    session = FakeSession()

    with pytest.raises(ValueError, match="Audit actor subject is required"):
        audit_service.add_audit_event(
            session,
            actor_sub="",
            actor_username=None,
            action="privilege.approve",
            target_user_id="user-456",
            outcome="success",
        )

    assert not session.added
    assert not session.committed


def test_add_audit_event_rejects_invalid_outcome():
    session = FakeSession()

    with pytest.raises(ValueError, match="Invalid audit outcome"):
        audit_service.add_audit_event(
            session,
            actor_sub="admin-123",
            actor_username="admin",
            action="privilege.approve",
            target_user_id="user-456",
            outcome="pending",
        )

    assert not session.added
    assert not session.committed
