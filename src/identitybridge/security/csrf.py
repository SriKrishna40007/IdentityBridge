import secrets
from collections.abc import Awaitable, Callable
from typing import Any

ASGIApp = Callable[..., Awaitable[None]]
SAFE_METHODS = {b"GET", b"HEAD", b"OPTIONS"}


class CSRFMiddleware:
    """Require a session-bound CSRF token for unsafe HTTP methods."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or scope["method"].encode() in SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        session = scope.get("session")
        expected_token = session.get("csrf_token") if isinstance(session, dict) else None

        supplied_token = next(
            (
                value.decode("latin-1")
                for name, value in scope.get("headers", [])
                if name.lower() == b"x-csrf-token"
            ),
            None,
        )

        if (
            not isinstance(expected_token, str)
            or not isinstance(supplied_token, str)
            or not secrets.compare_digest(expected_token, supplied_token)
        ):
            body = b'{"detail":"CSRF validation failed"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode("ascii")),
                    ],
                }
            )
            await send(
                {
                    "type": "http.response.body",
                    "body": body,
                }
            )
            return

        await self.app(scope, receive, send)
