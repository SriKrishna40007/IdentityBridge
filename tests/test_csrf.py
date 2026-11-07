from fastapi.testclient import TestClient

from identitybridge.config.settings import get_settings
from identitybridge.main import create_app


def test_csrf_token_endpoint_returns_session_token():
    client = TestClient(create_app(get_settings()))

    response = client.get("/auth/csrf")

    assert response.status_code == 200
    assert len(response.json()["csrf_token"]) >= 32


def test_csrf_token_is_stable_within_session():
    client = TestClient(create_app(get_settings()))

    first = client.get("/auth/csrf").json()["csrf_token"]
    second = client.get("/auth/csrf").json()["csrf_token"]

    assert first == second


def test_unsafe_request_without_csrf_token_is_rejected():
    client = TestClient(create_app(get_settings()))

    response = client.post("/auth/logout")

    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF validation failed"


def test_unsafe_request_with_invalid_csrf_token_is_rejected():
    client = TestClient(create_app(get_settings()))
    client.get("/auth/csrf")

    response = client.post(
        "/auth/logout",
        headers={"X-CSRF-Token": "invalid-token"},
    )

    assert response.status_code == 403


def test_unsafe_request_with_valid_csrf_token_is_accepted():
    client = TestClient(create_app(get_settings()))
    token = client.get("/auth/csrf").json()["csrf_token"]

    response = client.post(
        "/auth/logout",
        headers={
            "X-CSRF-Token": token,
            "Origin": "http://localhost:8000",
        },
    )

    assert response.status_code == 204


def test_safe_requests_do_not_require_csrf_token():
    client = TestClient(create_app(get_settings()))

    response = client.get("/health/live")

    assert response.status_code == 200
