from collections.abc import Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status


def get_current_user(request: Request) -> dict[str, Any]:
    """Return the authenticated user from the application session."""
    user = request.session.get("user")

    if not isinstance(user, dict) or not user.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    return user


def require_roles(*required_roles: str) -> Callable:
    """Require at least one specified client role."""

    if not required_roles or any(
        not isinstance(role, str) or not role.strip()
        for role in required_roles
    ):
        raise ValueError("At least one valid role must be specified")

    def role_checker(
        user: Annotated[dict[str, Any], Depends(get_current_user)],
    ) -> dict[str, Any]:
        user_roles = user.get("roles", [])

        if not isinstance(user_roles, list):
            user_roles = []

        if not set(required_roles).intersection(
            role for role in user_roles if isinstance(role, str)
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )

        return user

    return role_checker
