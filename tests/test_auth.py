from fastapi.testclient import TestClient

from identitybridge.main import app

client = TestClient(app)


def test_unauthenticated_user_cannot_access_profile() -> None:
    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"


def test_logout_clears_session() -> None:
    csrf_response = client.get("/auth/csrf")
    token = csrf_response.json()["csrf_token"]
    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": token,
            "Origin": "http://localhost:8000",
        },
    )

    assert response.status_code == 204


def test_auth_routes_are_in_openapi() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200

    paths = response.json()["paths"]
    assert "/auth/login" in paths
    assert "/auth/csrf" in paths
    assert "/auth/callback" in paths
    assert "/auth/me" in paths
    assert "/auth/logout" in paths
