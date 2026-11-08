from types import SimpleNamespace
from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from identitybridge.security.authorization import (
    get_current_user,
    require_roles,
)


class MockKeycloakAdmin:
    def __init__(self, roles=None, fail=False):
        self.roles = roles or []
        self.fail = fail
        self.calls = []

    async def get_user_client_roles(self, user_id, client_id):
        self.calls.append((user_id, client_id))
        if self.fail:
            raise RuntimeError("Keycloak unavailable")
        return [{"name": role} for role in self.roles]


def create_test_app(roles=None, fail=False):
    app = FastAPI()
    app.state.settings = SimpleNamespace(oidc_client_id="identitybridge-api")
    app.state.keycloak_admin = MockKeycloakAdmin(roles=roles, fail=fail)

    app.add_middleware(
        SessionMiddleware,
        secret_key="test-session-secret-that-is-long-enough",
    )

    @app.get("/test/session")
    async def session_test(
        user: Annotated[dict, Depends(get_current_user)],
    ):
        return user

    @app.get("/test/admin")
    async def admin_test(
        user: Annotated[dict, Depends(require_roles("identity-admin"))],
    ):
        return {"message": "admin access granted"}

    @app.get("/test/analyst")
    async def analyst_test(
        user: Annotated[
            dict,
            Depends(require_roles("security-analyst", "identity-admin")),
        ],
    ):
        return {"message": "analyst access granted"}

    return app


@pytest.fixture
def client():
    return TestClient(create_test_app())


def authenticate(client, roles):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": roles,
    }


def test_unauthenticated_user_receives_401(client):
    response = client.get("/test/session")
    assert response.status_code == 401


def test_authenticated_user_can_access_session(client):
    authenticate(client, ["standard-user"])

    response = client.get("/test/session")

    assert response.status_code == 200
    assert response.json()["sub"] == "test-user"


def test_user_with_current_required_role_receives_access():
    app = create_test_app(["identity-admin"])
    client = TestClient(app)
    authenticate(client, ["standard-user"])

    response = client.get("/test/admin")

    assert response.status_code == 200
    assert app.state.keycloak_admin.calls == [("test-user", "identitybridge-api")]


def test_stale_session_role_does_not_grant_access():
    app = create_test_app(["standard-user"])
    client = TestClient(app)
    authenticate(client, ["identity-admin"])

    response = client.get("/test/admin")

    assert response.status_code == 403


def test_current_role_refreshes_session_snapshot():
    app = create_test_app(["security-analyst"])
    client = TestClient(app)
    authenticate(client, ["standard-user"])

    response = client.get("/test/analyst")

    assert response.status_code == 200


def test_keycloak_failure_fails_closed():
    app = create_test_app(fail=True)
    client = TestClient(app)
    authenticate(client, ["identity-admin"])

    response = client.get("/test/admin")

    assert response.status_code == 503


def test_missing_keycloak_dependency_fails_closed():
    app = create_test_app(["identity-admin"])
    app.state.keycloak_admin = None
    client = TestClient(app)
    authenticate(client, ["identity-admin"])

    response = client.get("/test/admin")

    assert response.status_code == 503


def test_invalid_role_configuration_is_rejected():
    with pytest.raises(ValueError):
        require_roles()

    with pytest.raises(ValueError):
        require_roles("")
