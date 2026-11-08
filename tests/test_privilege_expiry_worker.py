from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from identitybridge.application import privilege_expiry_worker as worker


def make_claim(action="revoke_pending"):
    return (uuid4(), action, "target-123", "identity-admin")


def make_db(claim):
    db = MagicMock()
    return db


def claim_once(claim):
    """Return one claim, then report that the queue is empty."""
    batches = iter([[claim], []])
    return lambda db, *, now, batch_size: next(batches, [])


@pytest.mark.anyio
async def test_worker_removes_and_verifies_jit_role(monkeypatch):
    claim = make_claim()
    db = make_db(claim)
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(
        side_effect=[
            [{"name": "identity-admin"}],
            [],
        ]
    )
    admin.remove_client_role = AsyncMock()

    monkeypatch.setattr(
        worker,
        "claim_expired_privileges",
        claim_once(claim),
    )

    completed = []

    def complete(db, request_id, *, role_absent, now):
        completed.append((request_id, role_absent))
        return MagicMock(status="expired")

    monkeypatch.setattr(
        worker,
        "complete_privilege_revocation",
        complete,
    )

    result = await worker.process_expired_privileges(
        db,
        admin,
        client_id="identitybridge-client",
    )

    assert result["processed"] == 1
    assert result["expired"] == 1
    assert completed == [(claim[0], True)]

    admin.remove_client_role.assert_awaited_once_with(
        "target-123",
        "identitybridge-client",
        "identity-admin",
    )


@pytest.mark.anyio
async def test_worker_skips_preexisting_role_claim(monkeypatch):
    claim = make_claim("expired")
    db = make_db(claim)
    admin = MagicMock()

    monkeypatch.setattr(
        worker,
        "claim_expired_privileges",
        claim_once(claim),
    )

    result = await worker.process_expired_privileges(
        db,
        admin,
        client_id="identitybridge-client",
    )

    assert result["processed"] == 1
    assert result["expired"] == 1
    admin.get_user_client_roles.assert_not_called()
    admin.remove_client_role.assert_not_called()


@pytest.mark.anyio
async def test_worker_schedules_retry_when_keycloak_fails(monkeypatch):
    claim = make_claim()
    db = make_db(claim)
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(side_effect=RuntimeError("simulated Keycloak outage"))

    monkeypatch.setattr(
        worker,
        "claim_expired_privileges",
        claim_once(claim),
    )

    failures = []

    def complete(db, request_id, *, role_absent, now):
        failures.append((request_id, role_absent))
        return MagicMock(status="revoke_failed")

    monkeypatch.setattr(
        worker,
        "complete_privilege_revocation",
        complete,
    )

    result = await worker.process_expired_privileges(
        db,
        admin,
        client_id="identitybridge-client",
    )

    assert result["processed"] == 1
    assert result["retry_scheduled"] == 1
    assert failures == [(claim[0], False)]
    admin.remove_client_role.assert_not_called()


@pytest.mark.anyio
async def test_worker_reports_manual_reconciliation(monkeypatch):
    claim = make_claim("manual")
    db = make_db(claim)
    admin = MagicMock()

    monkeypatch.setattr(
        worker,
        "claim_expired_privileges",
        claim_once(claim),
    )

    result = await worker.process_expired_privileges(
        db,
        admin,
        client_id="identitybridge-client",
    )

    assert result["processed"] == 1
    assert result["manual_reconciliation"] == 1
    admin.get_user_client_roles.assert_not_called()


@pytest.mark.anyio
async def test_database_completion_failure_propagates(monkeypatch):
    claim = make_claim()
    db = make_db(claim)
    admin = MagicMock()
    admin.get_user_client_roles = AsyncMock(return_value=[])

    monkeypatch.setattr(
        worker,
        "claim_expired_privileges",
        claim_once(claim),
    )
    monkeypatch.setattr(
        worker,
        "complete_privilege_revocation",
        MagicMock(side_effect=RuntimeError("database unavailable")),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        await worker.process_expired_privileges(
            db,
            admin,
            client_id="identitybridge-client",
        )
