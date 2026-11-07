
import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.responses import RedirectResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


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

    return await oauth.keycloak.authorize_redirect(
        request,
        redirect_uri=settings.oidc_redirect_uri,
    )


@router.get("/callback", name="auth_callback")
async def auth_callback(request: Request) -> RedirectResponse:
    oauth = request.app.state.oauth
    settings = request.app.state.settings

    token = await oauth.keycloak.authorize_access_token(request)
    userinfo: Any = token.get("userinfo")

    if not isinstance(userinfo, dict) or not userinfo.get("sub"):
        raise HTTPException(
            status_code=401,
            detail="OIDC authentication did not return a valid user identity",
        )

    # Extract roles belonging specifically to the IdentityBridge API client.
    resource_access = userinfo.get("resource_access", {})

    if not isinstance(resource_access, dict):
        resource_access = {}

    client_access = resource_access.get(settings.oidc_client_id, {})

    if not isinstance(client_access, dict):
        client_access = {}

    roles = client_access.get("roles", [])

    if not isinstance(roles, list):
        roles = []

    # Rotate the CSRF token after successful authentication.
    request.session["csrf_token"] = secrets.token_urlsafe(32)

    # Store identity claims and validated role names only.
    # Never store access or refresh tokens in the session.
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
