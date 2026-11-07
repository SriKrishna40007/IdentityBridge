import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urlsplit

ASGIApp = Callable[..., Awaitable[None]]
SAFE_METHODS = {b"GET", b"HEAD", b"OPTIONS"}


def normalize_origin(value: str) -> tuple[str, str, int] | None:
    """Parse and normalize an HTTP(S) origin without accepting URL paths."""
    try:
        parsed = urlsplit(value)

        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            return None

        scheme = parsed.scheme.lower()
        hostname = parsed.hostname.lower()
        port = parsed.port or (443 if scheme == "https" else 80)

        return scheme, hostname, port
    except ValueError:
        return None


class OriginValidationMiddleware:
    """Reject unsafe requests from untrusted or missing browser origins."""

    def __init__(self, app: ASGIApp, trusted_origin: str) -> None:
        self.app = app
        self.trusted_origin = normalize_origin(trusted_origin)

        if self.trusted_origin is None:
            raise ValueError("Configured application origin is invalid.")

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[..., Awaitable[Any]],
        send: Callable[..., Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or scope["method"].encode() in SAFE_METHODS:
            await self.app(scope, receive, send)
            return

        origins = [
            value.decode("latin-1")
            for name, value in scope.get("headers", [])
            if name.lower() == b"origin"
        ]

        supplied_origin = normalize_origin(origins[0]) if len(origins) == 1 else None

        if supplied_origin != self.trusted_origin:
            body = json.dumps(
                {"detail": "Request origin is not allowed."}
            ).encode("utf-8")

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
