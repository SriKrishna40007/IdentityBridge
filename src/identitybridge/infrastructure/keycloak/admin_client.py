from typing import Any

import httpx

from identitybridge.config.settings import Settings


class KeycloakAdminClient:
    """Client for the Keycloak Admin REST API."""

    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._issuer_url = settings.oidc_issuer_url.rstrip("/")
        self._client_id = settings.keycloak_admin_client_id
        self._client_secret = settings.keycloak_admin_client_secret
        self._transport = transport

        if "/realms/" not in self._issuer_url:
            raise ValueError("OIDC issuer URL must contain /realms/{realm}")

        server_url, realm = self._issuer_url.split("/realms/", maxsplit=1)
        self._admin_url = f"{server_url}/admin/realms/{realm}"

    async def get_access_token(self) -> str:
        token_url = f"{self._issuer_url}/protocol/openid-connect/token"

        async with httpx.AsyncClient(
            timeout=10.0,
            transport=self._transport,
        ) as client:
            response = await client.post(
                token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )

        if response.status_code != 200:
            raise RuntimeError(
                f"Keycloak service-account authentication failed "
                f"(HTTP {response.status_code})"
            )

        payload = response.json()
        token = payload.get("access_token")

        if not isinstance(token, str) or not token:
            raise RuntimeError("Keycloak returned no access token")

        return token

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: dict[str, str] | None = None,
    ) -> httpx.Response:
        token = await self.get_access_token()

        async with httpx.AsyncClient(
            timeout=15.0,
            transport=self._transport,
        ) as client:
            response = await client.request(
                method,
                f"{self._admin_url}/{path.lstrip('/')}",
                headers={"Authorization": f"Bearer {token}"},
                json=json,
                params=params,
            )

        if response.status_code >= 400:
            raise RuntimeError(
                f"Keycloak Admin API request failed "
                f"(HTTP {response.status_code})"
            )

        return response

    async def find_users(self, username: str) -> list[dict[str, Any]]:
        response = await self._request(
            "GET",
            "users",
            params={"username": username, "exact": "true"},
        )
        result = response.json()
        return result if isinstance(result, list) else []

    async def create_user(
        self,
        *,
        username: str,
        email: str,
        first_name: str,
        last_name: str,
        enabled: bool = True,
    ) -> None:
        await self._request(
            "POST",
            "users",
            json={
                "username": username,
                "email": email,
                "firstName": first_name,
                "lastName": last_name,
                "enabled": enabled,
                "emailVerified": False,
            },
        )

    async def set_user_enabled(self, user_id: str, enabled: bool) -> None:
        await self._request(
            "PUT",
            f"users/{user_id}",
            json={"enabled": enabled},
        )

    async def get_client_uuid(self, client_id: str) -> str:
        response = await self._request(
            "GET",
            "clients",
            params={"clientId": client_id},
        )
        clients = response.json()

        if not isinstance(clients, list) or not clients:
            raise RuntimeError("Keycloak client was not found")

        client_uuid = clients[0].get("id")
        if not isinstance(client_uuid, str) or not client_uuid:
            raise RuntimeError("Keycloak client has no valid internal ID")

        return client_uuid

    async def get_user_client_roles(
        self,
        user_id: str,
        client_id: str,
    ) -> list[dict[str, Any]]:
        client_uuid = await self.get_client_uuid(client_id)
        response = await self._request(
            "GET",
            f"users/{user_id}/role-mappings/clients/{client_uuid}",
        )
        roles = response.json()
        return roles if isinstance(roles, list) else []

    async def assign_client_role(
        self,
        user_id: str,
        client_id: str,
        role_name: str,
    ) -> None:
        client_uuid = await self.get_client_uuid(client_id)
        response = await self._request(
            "GET",
            f"clients/{client_uuid}/roles/{role_name}",
        )
        role = response.json()

        await self._request(
            "POST",
            f"users/{user_id}/role-mappings/clients/{client_uuid}",
            json=[role],
        )

    async def remove_client_role(
        self,
        user_id: str,
        client_id: str,
        role_name: str,
    ) -> None:
        client_uuid = await self.get_client_uuid(client_id)
        response = await self._request(
            "GET",
            f"clients/{client_uuid}/roles/{role_name}",
        )
        role = response.json()

        await self._request(
            "DELETE",
            f"users/{user_id}/role-mappings/clients/{client_uuid}",
            json=[role],
        )
