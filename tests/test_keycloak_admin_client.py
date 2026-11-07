import httpx
import pytest

from identitybridge.config.settings import get_settings
from identitybridge.infrastructure.keycloak.admin_client import (
    KeycloakAdminClient,
)


@pytest.mark.anyio
async def test_service_account_token_is_acquired():
    async def handler(request):
        assert request.url.path.endswith(
            "/protocol/openid-connect/token"
        )
        assert request.method == "POST"
        assert request.content.decode().find("client_credentials") >= 0

        return httpx.Response(
            200,
            json={"access_token": "test-token"},
        )

    transport = httpx.MockTransport(handler)
    client = KeycloakAdminClient(get_settings(), transport=transport)

    token = await client.get_access_token()

    assert token == "test-token"


@pytest.mark.anyio
async def test_user_search_uses_bearer_token():
    async def handler(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "test-token"})

        assert request.headers["Authorization"] == "Bearer test-token"
        assert request.url.path.endswith("/admin/realms/identitybridge/users")
        assert request.url.params["username"] == "demo-user"

        return httpx.Response(
            200,
            json=[{"id": "user-123", "username": "demo-user"}],
        )

    client = KeycloakAdminClient(
        get_settings(),
        transport=httpx.MockTransport(handler),
    )

    users = await client.find_users("demo-user")

    assert users[0]["id"] == "user-123"


@pytest.mark.anyio
async def test_admin_api_errors_do_not_return_response_body():
    async def handler(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "test-token"})

        return httpx.Response(
            403,
            json={"error": "insufficient_scope", "sensitive": "not exposed"},
        )

    client = KeycloakAdminClient(
        get_settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(RuntimeError) as error:
        await client.find_users("demo-user")

    assert "403" in str(error.value)
    assert "sensitive" not in str(error.value)
