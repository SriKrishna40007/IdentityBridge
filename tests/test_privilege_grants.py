from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from identitybridge.application import privilege_grants


def make_request():
    request = MagicMock()
    request.id = uuid4()
    request.target_user_id = "target-123"
    request.role_name = "identity-admin"
    return request


@pytest.mark.anyio
async def test_preexisting_role_is_preserved(monkeypatch):
    request = make_request()
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(return_value=[{"name": "identity-admin"}])
    admin.assign_client_role = AsyncMock()

    monkeypatch.setattr(
        privilege_grants,
        "prepare_privilege_grant",
        lambda db, request_id: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_preexisting_role",
        lambda db, request_id, *, role_exists: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "activate_privilege_grant",
        lambda db, request_id, *, granted_by_jit: request,
    )

    result = await privilege_grants.grant_approved_privilege(
        MagicMock(),
        admin,
        request_id=request.id,
        client_id="identitybridge-client",
    )

    assert result is request
    admin.assign_client_role.assert_not_awaited()
    admin.get_user_client_roles.assert_awaited_once()
    assert request.role_name == "identity-admin"


@pytest.mark.anyio
async def test_verified_new_role_is_activated(monkeypatch):
    request = make_request()
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(
        side_effect=[
            [],
            [{"name": "identity-admin"}],
        ]
    )
    admin.assign_client_role = AsyncMock()

    recorded = []
    activated = []

    monkeypatch.setattr(
        privilege_grants,
        "prepare_privilege_grant",
        lambda db, request_id: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_preexisting_role",
        lambda db, request_id, *, role_exists: recorded.append(role_exists),
    )
    monkeypatch.setattr(
        privilege_grants,
        "activate_privilege_grant",
        lambda db, request_id, *, granted_by_jit: activated.append(granted_by_jit) or request,
    )

    result = await privilege_grants.grant_approved_privilege(
        MagicMock(),
        admin,
        request_id=request.id,
        client_id="identitybridge-client",
        exclusive_role_writer=True,
    )

    assert result is request
    assert recorded == [False]
    assert activated == [True]
    admin.assign_client_role.assert_awaited_once_with(
        "target-123",
        "identitybridge-client",
        "identity-admin",
    )
    assert admin.get_user_client_roles.await_count == 2


@pytest.mark.anyio
async def test_grant_is_blocked_without_exclusive_writer(monkeypatch):
    request = make_request()
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(return_value=[])
    admin.assign_client_role = AsyncMock()

    recorded = []
    ambiguous = []

    monkeypatch.setattr(
        privilege_grants,
        "prepare_privilege_grant",
        lambda db, request_id: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_preexisting_role",
        lambda db, request_id, *, role_exists: recorded.append(role_exists),
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_ambiguous_grant",
        lambda db, request_id: ambiguous.append(request_id) or request,
    )

    result = await privilege_grants.grant_approved_privilege(
        MagicMock(),
        admin,
        request_id=request.id,
        client_id="identitybridge-client",
    )

    assert result is request
    assert recorded == [False]
    assert ambiguous == [request.id]
    admin.assign_client_role.assert_not_awaited()


@pytest.mark.anyio
async def test_assignment_error_requires_reconciliation(monkeypatch):
    request = make_request()
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(return_value=[])
    admin.assign_client_role = AsyncMock(side_effect=RuntimeError("simulated Keycloak failure"))

    ambiguous = []

    monkeypatch.setattr(
        privilege_grants,
        "prepare_privilege_grant",
        lambda db, request_id: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_preexisting_role",
        lambda db, request_id, *, role_exists: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_ambiguous_grant",
        lambda db, request_id: ambiguous.append(request_id) or request,
    )

    result = await privilege_grants.grant_approved_privilege(
        MagicMock(),
        admin,
        request_id=request.id,
        client_id="identitybridge-client",
        exclusive_role_writer=True,
    )

    assert result is request
    assert ambiguous == [request.id]


@pytest.mark.anyio
async def test_unverified_assignment_requires_reconciliation(monkeypatch):
    request = make_request()
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(
        side_effect=[
            [],
            [],
        ]
    )
    admin.assign_client_role = AsyncMock()

    ambiguous = []

    monkeypatch.setattr(
        privilege_grants,
        "prepare_privilege_grant",
        lambda db, request_id: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_preexisting_role",
        lambda db, request_id, *, role_exists: request,
    )
    monkeypatch.setattr(
        privilege_grants,
        "record_ambiguous_grant",
        lambda db, request_id: ambiguous.append(request_id) or request,
    )

    result = await privilege_grants.grant_approved_privilege(
        MagicMock(),
        admin,
        request_id=request.id,
        client_id="identitybridge-client",
        exclusive_role_writer=True,
    )

    assert result is request
    assert ambiguous == [request.id]
    admin.assign_client_role.assert_awaited_once()
