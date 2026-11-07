from typing import Annotated

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from starlette.middleware.sessions import SessionMiddleware

from identitybridge.security.authorization import (
    get_current_user,
    require_roles,
)


def create_test_app() -> FastAPI:
    app = FastAPI()

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


def test_unauthenticated_user_receives_401(client):
    response = client.get("/test/session")
    assert response.status_code == 401


def test_authenticated_user_can_access_session(client):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": ["standard-user"],
    }

    response = client.get("/test/session")

    assert response.status_code == 200
    assert response.json()["sub"] == "test-user"


def test_user_with_required_role_receives_access(client):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": ["identity-admin"],
    }

    response = client.get("/test/admin")
    assert response.status_code == 200


def test_user_without_required_role_receives_403(client):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": ["standard-user"],
    }

    response = client.get("/test/admin")
    assert response.status_code == 403
    assert response.json()["detail"] == "Insufficient permissions"


def test_user_with_any_allowed_role_receives_access(client):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": ["identity-admin"],
    }

    response = client.get("/test/analyst")
    assert response.status_code == 200


def test_user_with_empty_roles_receives_403(client):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": [],
    }

    response = client.get("/test/admin")
    assert response.status_code == 403


def test_invalid_role_configuration_is_rejected():
    with pytest.raises(ValueError):
        require_roles()

    with pytest.raises(ValueError):
        require_roles("")
