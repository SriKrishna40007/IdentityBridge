from uuid import UUID

from fastapi.testclient import TestClient

from identitybridge.config.settings import get_settings
from identitybridge.main import create_app


def test_response_contains_server_generated_request_id():
    client = TestClient(create_app(get_settings()))

    response = client.get("/health/live")

    assert response.status_code == 200
    UUID(response.headers["x-request-id"])


def test_each_request_receives_a_unique_request_id():
    client = TestClient(create_app(get_settings()))

    first = client.get("/health/live")
    second = client.get("/health/live")

    assert first.headers["x-request-id"] != second.headers["x-request-id"]


def test_caller_supplied_request_id_is_not_trusted():
    client = TestClient(create_app(get_settings()))

    response = client.get(
        "/health/live",
        headers={"X-Request-ID": "attacker-controlled-id"},
    )

    assert response.status_code == 200
    assert response.headers["x-request-id"] != "attacker-controlled-id"
    UUID(response.headers["x-request-id"])


def test_csrf_rejection_also_contains_request_id():
    client = TestClient(create_app(get_settings()))

    response = client.post("/auth/logout")

    assert response.status_code == 403
    UUID(response.headers["x-request-id"])
