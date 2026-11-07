from collections.abc import Awaitable, Callable
from typing import Any

ASGIApp = Callable[..., Awaitable[None]]


class SecurityHeadersMiddleware:
    """Add defensive browser security headers to HTTP responses."""

    def __init__(self, app: ASGIApp, enable_hsts: bool = False) -> None:
        self.app = app
        self.enable_hsts = enable_hsts

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_security_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"permissions-policy",
                            b"camera=(), microphone=(), geolocation=()",
                        ),
                        (b"x-xss-protection", b"0"),
                    ]
                )

                if self.enable_hsts:
                    headers.append(
                        (
                            b"strict-transport-security",
                            b"max-age=31536000",
                        )
                    )

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_with_security_headers)
