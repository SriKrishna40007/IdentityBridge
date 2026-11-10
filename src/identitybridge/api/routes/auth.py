
import json
import logging
import secrets
import time
from typing import Any

from authlib.integrations.base_client.errors import OAuthError
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.responses import RedirectResponse

from identitybridge.security.oidc_assurance import validate_oidc_assurance

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

STEP_UP_ACR = "2"
STEP_UP_MAX_AGE_SECONDS = 300
STEP_UP_SESSION_KEY = "oidc_step_up_pending"


@router.get("/csrf")
async def get_csrf_token(request: Request) -> dict[str, str]:
    token = request.session.get("csrf_token")

    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token

    return {"csrf_token": token}


@router.get("/login")
async def login(request: Request) -> RedirectResponse:
    oauth = request.app.state.oauth
    settings = request.app.state.settings

    request.session.pop(STEP_UP_SESSION_KEY, None)

    return await oauth.keycloak.authorize_redirect(
        request,
        redirect_uri=settings.oidc_redirect_uri,
    )


@router.get("/step-up")
async def step_up(request: Request) -> RedirectResponse:
    user = request.session.get("user")

    if not isinstance(user, dict) or not user.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="Authentication required before step-up",
        )

    oauth = request.app.state.oauth
    settings = request.app.state.settings

    request.session[STEP_UP_SESSION_KEY] = {
        "sub": user["sub"],
        "created_at": int(time.time()),
    }

    claims = {
        "id_token": {
            "acr": {
                "essential": True,
                "values": [STEP_UP_ACR],
            }
        }
    }

    return await oauth.keycloak.authorize_redirect(
        request,
        redirect_uri=settings.oidc_redirect_uri,
        claims=json.dumps(claims, separators=(",", ":")),
        max_age=STEP_UP_MAX_AGE_SECONDS,
    )


@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request) -> RedirectResponse:
    oauth = request.app.state.oauth
    settings = request.app.state.settings

    step_up = request.session.get(STEP_UP_SESSION_KEY)

    try:
        token = await oauth.keycloak.authorize_access_token(request)
    except OAuthError as exc:
        request.session.pop(STEP_UP_SESSION_KEY, None)
        raise HTTPException(
            status_code=401,
            detail="OIDC authentication failed",
        ) from exc

    userinfo: Any = token.get("userinfo")

    if not isinstance(userinfo, dict) or not userinfo.get("sub"):
        request.session.pop(STEP_UP_SESSION_KEY, None)
        raise HTTPException(
            status_code=401,
            detail="OIDC authentication did not return a valid user identity",
        )

    if step_up is not None:
        if not isinstance(step_up, dict):
            request.session.pop(STEP_UP_SESSION_KEY, None)
            raise HTTPException(401, detail="Invalid step-up transaction")

        original_sub = step_up.get("sub")
        created_at = step_up.get("created_at")

        if (
            not isinstance(original_sub, str)
            or not isinstance(created_at, int)
            or isinstance(created_at, bool)
            or time.time() - created_at > 300
            or time.time() < created_at
            or userinfo["sub"] != original_sub
        ):
            request.session.pop(STEP_UP_SESSION_KEY, None)
            raise HTTPException(401, detail="Step-up transaction expired or invalid")

        try:
            validate_oidc_assurance(
                userinfo,
                required_acr=STEP_UP_ACR,
                max_age_seconds=STEP_UP_MAX_AGE_SECONDS,
            )
        except ValueError as exc:
            logger.warning(
                "OIDC step-up rejected: reason=%s acr=%r auth_time=%r "
                "amr=%r",
                str(exc),
                userinfo.get("acr"),
                userinfo.get("auth_time"),
                userinfo.get("amr"),
            )
            request.session.pop(STEP_UP_SESSION_KEY, None)
            raise HTTPException(
                status_code=401,
                detail="Required step-up authentication was not satisfied",
            ) from exc

        request.session.pop(STEP_UP_SESSION_KEY, None)
        request.session["assurance"] = {
            "sub": original_sub,
            "acr": STEP_UP_ACR,
            "verified_at": int(time.time()),
            "auth_time": userinfo["auth_time"],
        }

        return RedirectResponse(url="/", status_code=303)

    resource_access = userinfo.get("resource_access", {})

    if not isinstance(resource_access, dict):
        resource_access = {}

    client_access = resource_access.get(settings.oidc_client_id, {})

    if not isinstance(client_access, dict):
        client_access = {}

    roles = client_access.get("roles", [])

    if not isinstance(roles, list):
        roles = []

    request.session["csrf_token"] = secrets.token_urlsafe(32)

    request.session["user"] = {
        key: userinfo[key]
        for key in (
            "sub",
            "preferred_username",
            "email",
            "name",
            "given_name",
            "family_name",
        )
        if key in userinfo
    }

    request.session["user"]["roles"] = [
        role for role in roles if isinstance(role, str)
    ]

    request.session.pop("assurance", None)

    return RedirectResponse(url="/", status_code=303)


@router.get("/me")
async def current_user(request: Request) -> dict[str, Any]:
    user = request.session.get("user")

    if not isinstance(user, dict) or not user.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    return user


@router.post("/logout", status_code=204)
async def logout(request: Request) -> Response:
    request.session.clear()
    return Response(status_code=204)
