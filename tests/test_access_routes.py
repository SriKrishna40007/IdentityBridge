import pytest
from fastapi.testclient import TestClient

from identitybridge.main import create_app
from identitybridge.security.authorization import get_current_user


@pytest.fixture
def client():
    from identitybridge.config.settings import get_settings

    app = create_app(get_settings())
    return TestClient(app)


def authenticate_as(client, roles):
    client.app.dependency_overrides[get_current_user] = lambda: {
        "sub": "test-user",
        "roles": roles,
    }


@pytest.mark.parametrize(
    ("path", "roles", "expected"),
    [
        ("/api/v1/access/admin", ["identity-admin"], 200),
        ("/api/v1/access/admin", ["standard-user"], 403),
        ("/api/v1/access/security", ["security-analyst"], 200),
        ("/api/v1/access/security", ["identity-admin"], 200),
        ("/api/v1/access/security", ["standard-user"], 403),
        ("/api/v1/access/audit", ["auditor"], 200),
        ("/api/v1/access/audit", ["identity-admin"], 200),
        ("/api/v1/access/audit", ["security-analyst"], 403),
    ],
)
def test_role_protected_routes(client, path, roles, expected):
    authenticate_as(client, roles)

    response = client.get(path)

    assert response.status_code == expected


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/access/admin",
        "/api/v1/access/security",
        "/api/v1/access/audit",
    ],
)
def test_protected_routes_reject_unauthenticated_users(client, path):
    response = client.get(path)

    assert response.status_code == 401


def test_root_landing_endpoint(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "running"
