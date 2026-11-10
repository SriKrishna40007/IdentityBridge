import asyncio

from identitybridge.security.headers import SecurityHeadersMiddleware


def run_middleware(existing_headers, enable_hsts=False):
    async def scenario():
        captured = []

        async def app(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": existing_headers,
                }
            )

        async def receive():
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        async def send(message):
            captured.append(message)

        middleware = SecurityHeadersMiddleware(
            app,
            enable_hsts=enable_hsts,
        )

        await middleware(
            {"type": "http", "method": "GET", "path": "/"},
            receive,
            send,
        )

        return captured[0]["headers"]

    return asyncio.run(scenario())


def test_existing_security_headers_are_replaced_without_duplicates():
    headers = run_middleware(
        [
            (b"x-frame-options", b"SAMEORIGIN"),
            (b"x-frame-options", b"ALLOWALL"),
        ]
    )

    frame_headers = [value for name, value in headers if name.lower() == b"x-frame-options"]

    assert frame_headers == [b"DENY"]


def test_hsts_is_removed_when_disabled():
    headers = run_middleware(
        [(b"strict-transport-security", b"max-age=999")],
        enable_hsts=False,
    )

    assert not any(name.lower() == b"strict-transport-security" for name, _ in headers)


def test_hsts_is_set_when_enabled():
    headers = run_middleware(
        [(b"strict-transport-security", b"max-age=999")],
        enable_hsts=True,
    )

    hsts_headers = [
        value for name, value in headers if name.lower() == b"strict-transport-security"
    ]

    assert hsts_headers == [b"max-age=31536000"]
