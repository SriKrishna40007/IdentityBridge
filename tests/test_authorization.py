import time

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from identitybridge.security.authorization import require_recent_step_up

USER = {"sub": "user-123", "preferred_username": "test-user"}


def make_request(assurance: dict | None = None) -> Request:
    session = {"user": USER.copy()}
    if assurance is not None:
        session["assurance"] = assurance

    return Request({
        "type": "http",
        "method": "GET",
        "path": "/test",
        "headers": [],
        "session": session,
    })


def valid_assurance() -> dict:
    now = time.time()
    return {
        "sub": USER["sub"],
        "acr": "2",
        "verified_at": now,
        "auth_time": now - 60,
    }


def test_accepts_recent_step_up_for_same_user() -> None:
    request = make_request(valid_assurance())
    assert require_recent_step_up(request, USER.copy())["sub"] == USER["sub"]


def test_rejects_missing_assurance() -> None:
    request = make_request()
    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403
    assert exc.value.detail == "Step-up authentication required"


def test_rejects_assurance_for_different_user() -> None:
    assurance = valid_assurance()
    assurance["sub"] = "another-user"
    request = make_request(assurance)

    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403


@pytest.mark.parametrize("acr", ["1", "3", None, 2])
def test_rejects_incorrect_acr(acr: object) -> None:
    assurance = valid_assurance()
    assurance["acr"] = acr
    request = make_request(assurance)

    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403
    assert "assurance" not in request.session


def test_rejects_stale_authentication() -> None:
    assurance = valid_assurance()
    assurance["auth_time"] = time.time() - 301
    request = make_request(assurance)

    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403
    assert "assurance" not in request.session


def test_rejects_expired_step_up_verification() -> None:
    assurance = valid_assurance()
    assurance["verified_at"] = time.time() - 301
    request = make_request(assurance)

    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403
    assert "assurance" not in request.session


@pytest.mark.parametrize("verified_at", [float("nan"), float("inf"), float("-inf")])
def test_rejects_non_finite_verification_time(verified_at: float) -> None:
    assurance = valid_assurance()
    assurance["verified_at"] = verified_at
    request = make_request(assurance)

    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403
    assert "assurance" not in request.session


def test_rejects_future_verification_time() -> None:
    assurance = valid_assurance()
    assurance["verified_at"] = time.time() + 60
    request = make_request(assurance)

    with pytest.raises(HTTPException) as exc:
        require_recent_step_up(request, USER.copy())
    assert exc.value.status_code == 403
    assert "assurance" not in request.session
