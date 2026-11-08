from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from identitybridge.api.routes import privileges as privilege_routes
from identitybridge.application.audit import get_audit_writer
from identitybridge.infrastructure.audit_models import AuditEvent
from identitybridge.infrastructure.database import get_db
from identitybridge.infrastructure.privilege_request_models import PrivilegeRequest
from identitybridge.main import create_app
from identitybridge.security.authorization import get_current_user


class MockKeycloakAdmin:
    async def get_user_client_roles(self, user_id, client_id):
        return [{"name": "identity-admin"}]


def make_request():
    return PrivilegeRequest(
        id=uuid4(),
        requester_sub="requester-123",
        target_user_id="requester-123",
        role_name="identity-admin",
        justification="Emergency production access is required.",
        status="pending",
        requested_duration_minutes=60,
        requested_at=datetime.now(UTC),
    )


@pytest.fixture
def api_context(monkeypatch):
    app = create_app()
    app.state.keycloak_admin = MockKeycloakAdmin()

    item = make_request()
    db = MagicMock()
    db.scalar.return_value = item

    audit_events = []

    def fake_audit_writer(**event):
        audit_events.append(event)

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = lambda: {
        "sub": "approver-789",
        "preferred_username": "test-admin",
        "roles": ["identity-admin"],
    }
    app.dependency_overrides[get_audit_writer] = lambda: fake_audit_writer

    async def fake_grant_approved_privilege(
        db,
        admin,
        *,
        request_id,
        client_id,
        exclusive_role_writer=False,
    ):
        # Keep this test isolated: never call Keycloak grant operations.
        return item

    monkeypatch.setattr(
        privilege_routes,
        "grant_approved_privilege",
        fake_grant_approved_privilege,
    )

    with TestClient(app) as client:
        csrf = client.get("/auth/csrf")
        assert csrf.status_code == 200

        client.headers.update(
            {
                "X-CSRF-Token": csrf.json()["csrf_token"],
                "Origin": "http://localhost:8000",
            }
        )

        yield SimpleNamespace(
            client=client,
            item=item,
            db=db,
            audit_events=audit_events,
        )

    app.dependency_overrides.clear()


def test_approval_comment_is_persisted_and_returned(api_context):
    comment = "Approved for the production incident investigation."

    response = api_context.client.post(
        f"/api/v1/privileges/{api_context.item.id}/approve",
        json={"comment": comment},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "approved"
    assert response.json()["approver_sub"] == "approver-789"
    assert response.json()["decision_comment"] == comment
    assert api_context.item.decision_comment == comment
    assert api_context.audit_events[0]["action"] == "privilege.grant"
    transactional_events = [
        call.args[0]
        for call in api_context.db.add.call_args_list
        if isinstance(call.args[0], AuditEvent)
    ]
    assert len(transactional_events) == 1
    assert transactional_events[0].action == "privilege.approve"
    assert transactional_events[0].outcome == "success"
    assert "decision_comment" not in transactional_events[0].details


def test_rejection_comment_is_persisted_and_returned(api_context):
    comment = "Rejected because the requested access is not justified."

    response = api_context.client.post(
        f"/api/v1/privileges/{api_context.item.id}/reject",
        json={"comment": comment},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "rejected"
    assert response.json()["approver_sub"] == "approver-789"
    assert response.json()["decision_comment"] == comment
    assert api_context.item.decision_comment == comment
    transactional_events = [
        call.args[0]
        for call in api_context.db.add.call_args_list
        if isinstance(call.args[0], AuditEvent)
    ]
    assert len(transactional_events) == 1
    assert transactional_events[0].action == "privilege.reject"
    assert transactional_events[0].outcome == "success"
    assert "decision_comment" not in transactional_events[0].details


@pytest.mark.parametrize("action", ["approve", "reject"])
def test_decision_without_comment_returns_null(api_context, action):
    response = api_context.client.post(
        f"/api/v1/privileges/{api_context.item.id}/{action}",
        json={},
    )

    assert response.status_code == 200
    assert response.json()["decision_comment"] is None
    assert api_context.item.decision_comment is None


def test_non_admin_cannot_decide_privilege_request(api_context):
    async def get_no_roles(user_id, client_id):
        return []

    api_context.client.app.state.keycloak_admin.get_user_client_roles = get_no_roles

    response = api_context.client.post(
        f"/api/v1/privileges/{api_context.item.id}/reject",
        json={"comment": "Not authorized."},
    )

    assert response.status_code == 403
    assert api_context.item.status == "pending"
    assert api_context.db.commit.call_count == 0
