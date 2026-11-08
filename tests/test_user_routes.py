import pytest
from fastapi.testclient import TestClient

from identitybridge.application.audit import get_audit_writer
from identitybridge.config.settings import get_settings
from identitybridge.main import create_app
from identitybridge.security.authorization import get_current_user


class MockAdminClient:
    def __init__(self):
        self.roles = ["standard-user"]

    async def find_users(self, username):
        if username == "existing-user":
            return [{"id": "user-123", "username": username}]
        return []

    async def create_user(self, **kwargs):
        return None

    async def set_user_enabled(self, user_id, enabled):
        return None

    async def get_user_client_roles(self, user_id, client_id):
        if user_id == "test-admin":
            return [{"name": role} for role in self.roles]
        return [{"name": "standard-user"}]

    async def assign_client_role(self, user_id, client_id, role_name):
        return None

    async def remove_client_role(self, user_id, client_id, role_name):
        return None


@pytest.fixture
def client():
    app = create_app(get_settings())
    app.state.keycloak_admin = MockAdminClient()
    app.state.audit_events = []

    def fake_audit_writer(**event):
        app.state.audit_events.append(event)

    app.dependency_overrides[get_audit_writer] = lambda: fake_audit_writer
    return TestClient(app)


def authenticate(client, roles):
    client.app.state.keycloak_admin.roles = list(roles)
    csrf_response = client.get("/auth/csrf")
    assert csrf_response.status_code == 200
    client.headers.update(
        {"X-CSRF-Token": csrf_response.json()["csrf_token"], "Origin": "http://localhost:8000"}
    )
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-admin",
        "preferred_username": "test-admin",
        "roles": roles,
    }


def test_user_management_rejects_unauthenticated_requests(client):
    response = client.get(
        "/api/v1/admin/users",
        params={"username": "demo"},
    )
    assert response.status_code == 401


def test_standard_user_cannot_manage_users(client):
    authenticate(client, ["standard-user"])

    response = client.get(
        "/api/v1/admin/users",
        params={"username": "demo"},
    )
    assert response.status_code == 403


def test_admin_can_search_users(client):
    authenticate(client, ["identity-admin"])

    response = client.get(
        "/api/v1/admin/users",
        params={"username": "existing-user"},
    )

    assert response.status_code == 200
    assert response.json() == [{"id": "user-123", "username": "existing-user"}]


def test_admin_can_provision_user(client):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users",
        json={
            "username": "new-user",
            "email": "new@example.test",
            "first_name": "New",
            "last_name": "User",
        },
    )

    assert response.status_code == 201
    assert response.json()["status"] == "created"


def test_duplicate_username_is_rejected(client):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users",
        json={
            "username": "existing-user",
            "email": "existing@example.test",
            "first_name": "Existing",
            "last_name": "User",
        },
    )

    assert response.status_code == 409


def test_admin_can_disable_user(client):
    authenticate(client, ["identity-admin"])

    response = client.patch(
        "/api/v1/admin/users/user-123/status",
        json={"enabled": False},
    )

    assert response.status_code == 200
    assert response.json()["enabled"] is False


def test_admin_can_read_user_roles(client):
    authenticate(client, ["identity-admin"])

    response = client.get("/api/v1/admin/users/user-123/roles")

    assert response.status_code == 200
    assert response.json() == ["standard-user"]


@pytest.mark.parametrize(
    "role",
    ["identity-admin", "security-analyst", "auditor"],
)
def test_admin_cannot_assign_privileged_role_directly(client, role):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users/user-123/roles",
        json={"role": role},
    )

    assert response.status_code == 403
    assert "JIT approval workflow" in response.json()["detail"]


@pytest.mark.parametrize(
    "role",
    ["identity-admin", "security-analyst", "auditor"],
)
def test_admin_cannot_remove_privileged_role_directly(client, role):
    authenticate(client, ["identity-admin"])

    response = client.delete(f"/api/v1/admin/users/user-123/roles/{role}")

    assert response.status_code == 403
    assert "JIT workflow" in response.json()["detail"]


def test_unapproved_role_assignment_is_rejected(client):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users/user-123/roles",
        json={"role": "realm-admin"},
    )

    assert response.status_code == 422


def test_admin_can_remove_approved_role(client):
    authenticate(client, ["identity-admin"])

    response = client.delete("/api/v1/admin/users/user-123/roles/standard-user")

    assert response.status_code == 204


def test_unapproved_role_removal_is_rejected(client):
    authenticate(client, ["identity-admin"])

    response = client.delete("/api/v1/admin/users/user-123/roles/realm-admin")

    assert response.status_code == 422


def test_invalid_user_payload_is_rejected(client):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users",
        json={
            "username": "ab",
            "email": "not-an-email",
            "first_name": "",
            "last_name": "User",
            "enabled": True,
        },
    )

    assert response.status_code == 422


def test_user_search_does_not_expose_unapproved_fields(client):
    authenticate(client, ["identity-admin"])

    class SensitiveMock(MockAdminClient):
        async def find_users(self, username):
            return [
                {
                    "id": "user-123",
                    "username": username,
                    "email": "user@example.test",
                    "credentials": [{"type": "password"}],
                    "access": {"manage": True},
                    "secret": "must-not-leak",
                }
            ]

    client.app.state.keycloak_admin = SensitiveMock()
    client.app.state.keycloak_admin.roles = ["identity-admin"]

    response = client.get(
        "/api/v1/admin/users",
        params={"username": "demo"},
    )

    assert response.status_code == 200
    body = response.json()[0]

    assert body["username"] == "demo"
    assert "credentials" not in body
    assert "access" not in body
    assert "secret" not in body


def test_user_management_routes_are_in_openapi(client):
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]

    assert "/api/v1/admin/users" in paths
    assert "/api/v1/admin/users/{user_id}/status" in paths
    assert "/api/v1/admin/users/{user_id}/roles" in paths


def test_provision_user_records_successful_audit_event(client):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users",
        headers={"X-Request-ID": "request-provision-001"},
        json={
            "username": "new-user",
            "email": "private@example.test",
            "first_name": "New",
            "last_name": "User",
        },
    )

    assert response.status_code == 201
    event = client.app.state.audit_events[-1]
    assert event["actor_sub"] == "test-admin"
    assert event["actor_username"] == "test-admin"
    assert event["action"] == "user.provision"
    assert event["outcome"] == "success"
    assert event["request_id"] == response.headers["x-request-id"]
    assert event["request_id"] != "request-provision-001"
    assert event["details"] == {"username": "new-user"}
    assert "email" not in event["details"]


def test_user_status_update_records_successful_audit_event(client):
    authenticate(client, ["identity-admin"])

    response = client.patch(
        "/api/v1/admin/users/user-123/status",
        json={"enabled": False},
    )

    assert response.status_code == 200
    event = client.app.state.audit_events[-1]
    assert event["action"] == "user.status.update"
    assert event["target_user_id"] == "user-123"
    assert event["outcome"] == "success"
    assert event["details"] == {"enabled": False}


def test_standard_user_assignment_records_successful_audit_event(client):
    authenticate(client, ["identity-admin"])

    response = client.post(
        "/api/v1/admin/users/user-123/roles",
        json={"role": "standard-user"},
    )

    assert response.status_code == 204
    event = client.app.state.audit_events[-1]
    assert event["action"] == "user.role.assign"
    assert event["target_user_id"] == "user-123"
    assert event["outcome"] == "success"
    assert event["details"] == {"role": "standard-user"}


def test_role_removal_records_successful_audit_event(client):
    authenticate(client, ["identity-admin"])

    response = client.delete("/api/v1/admin/users/user-123/roles/standard-user")

    assert response.status_code == 204
    event = client.app.state.audit_events[-1]
    assert event["action"] == "user.role.remove"
    assert event["target_user_id"] == "user-123"
    assert event["outcome"] == "success"
    assert event["details"] == {"role": "standard-user"}


def test_keycloak_failure_records_failed_audit_event(client):
    authenticate(client, ["identity-admin"])

    class FailingAdminClient(MockAdminClient):
        async def set_user_enabled(self, user_id, enabled):
            raise RuntimeError("Simulated identity-provider failure")

    client.app.state.keycloak_admin = FailingAdminClient()
    client.app.state.keycloak_admin.roles = ["identity-admin"]

    response = client.patch(
        "/api/v1/admin/users/user-123/status",
        json={"enabled": False},
    )

    assert response.status_code == 502
    event = client.app.state.audit_events[-1]
    assert event["action"] == "user.status.update"
    assert event["target_user_id"] == "user-123"
    assert event["outcome"] == "failure"


def test_audit_failure_returns_service_unavailable(client):
    authenticate(client, ["identity-admin"])

    def failing_audit_writer(**event):
        raise RuntimeError("Simulated database failure")

    client.app.dependency_overrides[get_audit_writer] = lambda: failing_audit_writer

    response = client.patch(
        "/api/v1/admin/users/user-123/status",
        json={"enabled": False},
    )

    assert response.status_code == 503
    assert "audit persistence failed" in response.json()["detail"]
