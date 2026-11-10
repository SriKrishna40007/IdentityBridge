import asyncio
import time

import pytest
from authlib.integrations.base_client.errors import OAuthError
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from identitybridge.api.routes.auth import auth_callback
from identitybridge.main import app

client = TestClient(app)


def make_callback_request(session: dict) -> Request:
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/auth/callback",
        "raw_path": b"/auth/callback",
        "query_string": b"",
        "headers": [],
        "client": ("testclient", 50000),
        "server": ("testserver", 80),
        "app": app,
        "session": session,
    }
    return Request(scope)


def pending_step_up() -> dict:
    return {
        "sub": "user-123",
        "created_at": int(time.time()),
    }


def valid_step_up_userinfo() -> dict:
    return {
        "sub": "user-123",
        "acr": "2",
        "auth_time": time.time() - 30,
    }


def mock_oauth(monkeypatch, result=None, error=None) -> None:
    async def authorize_access_token(request):
        if error is not None:
            raise error
        return result

    monkeypatch.setattr(
        app.state.oauth.keycloak,
        "authorize_access_token",
        authorize_access_token,
    )


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


def test_step_up_callback_stores_subject_and_assurance(monkeypatch) -> None:
    session = {"oidc_step_up_pending": pending_step_up()}
    mock_oauth(
        monkeypatch,
        result={"userinfo": valid_step_up_userinfo()},
    )

    response = asyncio.run(auth_callback(make_callback_request(session)))

    assert response.status_code == 303
    assert "oidc_step_up_pending" not in session
    assert session["assurance"]["sub"] == "user-123"
    assert session["assurance"]["acr"] == "2"
    assert session["assurance"]["auth_time"] > time.time() - 300


def test_step_up_callback_rejects_different_subject(monkeypatch) -> None:
    session = {"oidc_step_up_pending": pending_step_up()}
    userinfo = valid_step_up_userinfo()
    userinfo["sub"] = "different-user"
    mock_oauth(monkeypatch, result={"userinfo": userinfo})

    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_callback(make_callback_request(session)))

    assert exc.value.status_code == 401
    assert "oidc_step_up_pending" not in session
    assert "assurance" not in session


@pytest.mark.parametrize(
    "claim_changes",
    [
        {"acr": "1"},
        {"acr": None},
        {"auth_time": time.time() - 301},
    ],
)
def test_step_up_callback_rejects_insufficient_assurance(
    monkeypatch,
    claim_changes: dict,
) -> None:
    session = {"oidc_step_up_pending": pending_step_up()}
    userinfo = valid_step_up_userinfo()
    userinfo.update(claim_changes)
    mock_oauth(monkeypatch, result={"userinfo": userinfo})

    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_callback(make_callback_request(session)))

    assert exc.value.status_code == 401
    assert "oidc_step_up_pending" not in session
    assert "assurance" not in session


def test_step_up_callback_clears_pending_transaction_on_oauth_error(
    monkeypatch,
) -> None:
    session = {"oidc_step_up_pending": pending_step_up()}
    mock_oauth(monkeypatch, error=OAuthError(error="access_denied"))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(auth_callback(make_callback_request(session)))

    assert exc.value.status_code == 401
    assert "oidc_step_up_pending" not in session
    assert "assurance" not in session
