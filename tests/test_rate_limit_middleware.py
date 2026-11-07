from fastapi.testclient import TestClient

from identitybridge.config.settings import get_settings
from identitybridge.infrastructure.rate_limit_service import RateLimitDecision
from identitybridge.main import create_app
from identitybridge.security.rate_limit import RATE_LIMITED_PATHS


def create_test_app(checker):
    settings = get_settings()
    application = create_app(settings)
    application.state.rate_limit_checker = checker
    return application


def test_allowed_request_passes_through_rate_limit_middleware():
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return RateLimitDecision(allowed=True, count=1, retry_after=60)

    app = create_test_app(checker)

    with TestClient(app) as client:
        response = client.get("/auth/csrf")

    assert response.status_code == 200
    assert len(response.json()["csrf_token"]) >= 32
    assert len(calls) == 1
    assert calls[0]["scope"] == "csrf"
    assert calls[0]["client_identifier"] == "testclient"


def test_rejected_request_returns_429_and_retry_after():
    def checker(**kwargs):
        return RateLimitDecision(allowed=False, count=31, retry_after=42)

    app = create_test_app(checker)

    with TestClient(app) as client:
        response = client.get("/auth/csrf")

    assert response.status_code == 429
    assert response.json() == {"detail": "Too many requests"}
    assert response.headers["retry-after"] == "42"
    assert response.headers.get("x-request-id")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_rate_limit_service_failure_fails_closed():
    def checker(**kwargs):
        raise RuntimeError("simulated database failure")

    app = create_test_app(checker)

    with TestClient(app) as client:
        response = client.get("/auth/csrf")

    assert response.status_code == 503
    assert response.json() == {
        "detail": "Rate limit service temporarily unavailable"
    }
    assert response.headers.get("x-request-id")


def test_forwarded_for_header_is_not_trusted():
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return RateLimitDecision(allowed=True, count=1, retry_after=60)

    app = create_test_app(checker)

    with TestClient(app) as client:
        response = client.get(
            "/auth/csrf",
            headers={"X-Forwarded-For": "203.0.113.99"},
        )

    assert response.status_code == 200
    assert calls[0]["client_identifier"] == "testclient"
    assert calls[0]["client_identifier"] != "203.0.113.99"


def test_non_target_routes_and_methods_are_not_rate_limited():
    calls = []

    def checker(**kwargs):
        calls.append(kwargs)
        return RateLimitDecision(allowed=True, count=1, retry_after=60)

    app = create_test_app(checker)

    with TestClient(app) as client:
        health_response = client.get("/health/live")
        method_response = client.post("/auth/csrf")

    assert health_response.status_code == 200
    assert method_response.status_code == 403
    assert calls == []


def test_oidc_callback_is_excluded_from_rate_limiting():
    assert "/auth/callback" not in RATE_LIMITED_PATHS
