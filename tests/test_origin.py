import pytest
from fastapi.testclient import TestClient

from identitybridge.config.settings import get_settings
from identitybridge.main import create_app

TRUSTED_ORIGIN = "http://localhost:8000"


@pytest.fixture
def client():
    settings = get_settings().model_copy(
        update={"app_origin": TRUSTED_ORIGIN}
    )
    return TestClient(create_app(settings))


def post_with_csrf(client, origin_headers=None):
    token = client.get("/auth/csrf").json()["csrf_token"]
    headers = {"X-CSRF-Token": token}

    if origin_headers:
        headers.update(origin_headers)

    return client.post("/auth/logout", headers=headers)


def test_same_origin_request_is_accepted(client):
    response = post_with_csrf(
        client,
        {"Origin": TRUSTED_ORIGIN},
    )

    assert response.status_code == 204


@pytest.mark.parametrize(
    "origin",
    [
        "https://attacker.example",
        "http://localhost:8001",
        "null",
        "not-a-valid-origin",
        "http://localhost:8000.evil.example",
        "http://localhost:8000/path",
    ],
)
def test_untrusted_origin_is_rejected(client, origin):
    response = post_with_csrf(client, {"Origin": origin})

    assert response.status_code == 403
    assert response.json()["detail"] == "Request origin is not allowed."


def test_missing_origin_is_rejected(client):
    response = post_with_csrf(client)

    assert response.status_code == 403


def test_duplicate_origin_headers_are_rejected(client):
    token = client.get("/auth/csrf").json()["csrf_token"]

    response = client.post(
        "/auth/logout",
        headers=[
            ("X-CSRF-Token", token),
            ("Origin", TRUSTED_ORIGIN),
            ("Origin", "https://attacker.example"),
        ],
    )

    assert response.status_code == 403


def test_safe_request_does_not_require_origin(client):
    response = client.get("/health/live")

    assert response.status_code == 200


def test_rejected_origin_response_contains_request_id(client):
    response = post_with_csrf(
        client,
        {"Origin": "https://attacker.example"},
    )

    assert response.status_code == 403
    assert response.headers.get("x-request-id")
