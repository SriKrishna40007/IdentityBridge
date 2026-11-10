
import math
import time
from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status

from identitybridge.security.oidc_assurance import validate_oidc_assurance


def get_current_user(request: Request) -> dict[str, Any]:
    """Return the authenticated user from the application session."""
    user = request.session.get("user")

    if not isinstance(user, dict) or not user.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return user


def require_recent_step_up(
    request: Request,
    user: Annotated[dict[str, Any], Depends(get_current_user)],
) -> dict[str, Any]:
    """Require recent LoA2 authentication for sensitive operations."""
    assurance = request.session.get("assurance")

    if not isinstance(assurance, dict):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Step-up authentication required",
        )

    if assurance.get("sub") != user["sub"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Step-up authentication required",
        )

    verified_at = assurance.get("verified_at")
    current_time = time.time()

    if (
        isinstance(verified_at, bool)
        or not isinstance(verified_at, (int, float))
        or not math.isfinite(verified_at)
        or current_time < verified_at
        or current_time - verified_at > 300
    ):
        request.session.pop("assurance", None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Step-up authentication expired",
        )

    try:
        validate_oidc_assurance(
            {
                "acr": assurance.get("acr"),
                "auth_time": assurance.get("auth_time"),
            },
            required_acr="2",
            max_age_seconds=300,
        )
    except ValueError as exc:
        request.session.pop("assurance", None)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Step-up authentication required",
        ) from exc

    return user


def require_roles(*required_roles: str) -> Callable:
    """Require current Keycloak client roles, not stale session claims."""

    if not required_roles or any(
        not isinstance(role, str) or not role.strip() for role in required_roles
    ):
        raise ValueError("At least one valid role must be specified")

    async def role_checker(
        request: Request,
        user: Annotated[dict[str, Any], Depends(get_current_user)],
    ) -> dict[str, Any]:
        admin = getattr(request.app.state, "keycloak_admin", None)
        settings = getattr(request.app.state, "settings", None)
        client_id = getattr(settings, "oidc_client_id", None)

        if admin is None or not isinstance(client_id, str) or not client_id:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Current permissions could not be verified",
            )

        try:
            role_mappings = await admin.get_user_client_roles(
                user["sub"],
                client_id,
            )
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Current permissions could not be verified",
            ) from None

        if not isinstance(role_mappings, list):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Current permissions could not be verified",
            )

        current_roles = [
            item["name"]
            for item in role_mappings
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]

        # Refresh the session snapshot after successful verification.
        user["roles"] = current_roles
        request.session["user"] = user

        if not set(required_roles).intersection(current_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return user

    return role_checker
