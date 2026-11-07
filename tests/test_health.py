from fastapi.testclient import TestClient

from identitybridge.main import app

client = TestClient(app)


def test_liveness_returns_alive() -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}


def test_openapi_documentation_is_available() -> None:
    response = client.get("/openapi.json")

    assert response.status_code == 200
    assert response.json()["info"]["title"] == "IdentityBridge"
