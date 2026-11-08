import httpx
import pytest

from identitybridge.config.settings import get_settings
from identitybridge.infrastructure.keycloak.admin_client import (
    KeycloakAdminClient,
)


@pytest.mark.anyio
async def test_service_account_token_is_acquired():
    async def handler(request):
        assert request.url.path.endswith("/protocol/openid-connect/token")
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


@pytest.mark.anyio
async def test_get_user_client_roles_returns_role_mappings():
    async def handler(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "test-token"})

        if request.method == "GET" and request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[{"id": "client-uuid"}])

        assert request.method == "GET"
        assert request.url.path.endswith("/users/user-123/role-mappings/clients/client-uuid")
        return httpx.Response(
            200,
            json=[{"id": "role-uuid", "name": "identity-admin"}],
        )

    client = KeycloakAdminClient(
        get_settings(),
        transport=httpx.MockTransport(handler),
    )

    roles = await client.get_user_client_roles("user-123", "identitybridge-client")

    assert roles == [{"id": "role-uuid", "name": "identity-admin"}]


@pytest.mark.anyio
async def test_assign_client_role_posts_role_mapping():
    async def handler(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "test-token"})

        if request.method == "GET" and request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[{"id": "client-uuid"}])

        if request.method == "GET" and request.url.path.endswith(
            "/clients/client-uuid/roles/identity-admin"
        ):
            return httpx.Response(
                200,
                json={"id": "role-uuid", "name": "identity-admin"},
            )

        assert request.method == "POST"
        assert request.url.path.endswith("/users/user-123/role-mappings/clients/client-uuid")
        assert request.read()
        assert b'"name":"identity-admin"' in request.content

        return httpx.Response(204)

    client = KeycloakAdminClient(
        get_settings(),
        transport=httpx.MockTransport(handler),
    )

    await client.assign_client_role(
        "user-123",
        "identitybridge-client",
        "identity-admin",
    )


@pytest.mark.anyio
async def test_remove_client_role_deletes_role_mapping():
    async def handler(request):
        if request.url.path.endswith("/protocol/openid-connect/token"):
            return httpx.Response(200, json={"access_token": "test-token"})

        if request.method == "GET" and request.url.path.endswith("/clients"):
            return httpx.Response(200, json=[{"id": "client-uuid"}])

        if request.method == "GET" and request.url.path.endswith(
            "/clients/client-uuid/roles/identity-admin"
        ):
            return httpx.Response(
                200,
                json={"id": "role-uuid", "name": "identity-admin"},
            )

        assert request.method == "DELETE"
        assert request.url.path.endswith("/users/user-123/role-mappings/clients/client-uuid")
        assert b'"name":"identity-admin"' in request.content

        return httpx.Response(204)

    client = KeycloakAdminClient(
        get_settings(),
        transport=httpx.MockTransport(handler),
    )

    await client.remove_client_role(
        "user-123",
        "identitybridge-client",
        "identity-admin",
    )
