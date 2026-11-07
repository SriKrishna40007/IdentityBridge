import logging
from collections.abc import Awaitable, Callable
from functools import partial
from typing import Any

from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse

from identitybridge.infrastructure.rate_limit_service import consume_rate_limit

ASGIApp = Callable[..., Awaitable[None]]
logger = logging.getLogger(__name__)

RATE_LIMITED_PATHS = {
    "/auth/login": ("login", "login_rate_limit"),
    "/auth/csrf": ("csrf", "csrf_rate_limit"),
}


class RateLimitMiddleware:
    """Apply persistent IP-based limits to authentication entry points."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or scope["method"] != "GET":
            await self.app(scope, receive, send)
            return

        route_config = RATE_LIMITED_PATHS.get(scope.get("path", ""))
        if route_config is None:
            await self.app(scope, receive, send)
            return

        rate_scope, limit_setting = route_config
        client = scope.get("client")
        client_identifier = client[0] if client else None
        application = scope.get("app")
        settings = getattr(getattr(application, "state", None), "settings", None)

        if (
            not isinstance(client_identifier, str)
            or not client_identifier
            or settings is None
        ):
            response = JSONResponse(
                {"detail": "Rate limit service temporarily unavailable"},
                status_code=503,
            )
            await response(scope, receive, send)
            return

        checker = getattr(
            getattr(application, "state", None),
            "rate_limit_checker",
            consume_rate_limit,
        )

        try:
            decision = await run_in_threadpool(
                partial(
                    checker,
                    scope=rate_scope,
                    client_identifier=client_identifier,
                    secret=settings.session_secret,
                    limit=getattr(settings, limit_setting),
                    window_seconds=settings.rate_limit_window_seconds,
                )
            )
        except Exception:
            logger.exception("Authentication rate-limit check failed")
            response = JSONResponse(
                {"detail": "Rate limit service temporarily unavailable"},
                status_code=503,
            )
            await response(scope, receive, send)
            return

        if not decision.allowed:
            response = JSONResponse(
                {"detail": "Too many requests"},
                status_code=429,
                headers={"Retry-After": str(decision.retry_after)},
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)
