from fastapi.testclient import TestClient

from identitybridge.config.settings import get_settings
from identitybridge.main import create_app


def test_security_headers_are_present():
    client = TestClient(create_app(get_settings()))

    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )
    assert response.headers["x-xss-protection"] == "0"


def test_hsts_is_not_enabled_in_development():
    settings = get_settings().model_copy(
        update={"app_environment": "development"}
    )
    client = TestClient(create_app(settings))

    response = client.get("/health/live")

    assert "strict-transport-security" not in response.headers


def test_hsts_is_enabled_in_production():
    settings = get_settings().model_copy(
        update={"app_environment": "production"}
    )
    client = TestClient(create_app(settings))

    response = client.get("/health/live")

    assert response.headers["strict-transport-security"] == (
        "max-age=31536000"
    )
