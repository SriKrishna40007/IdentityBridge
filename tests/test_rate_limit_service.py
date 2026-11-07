from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from identitybridge.infrastructure.rate_limit_service import (
    RateLimitDecision,
    calculate_window_start,
    consume_rate_limit,
    hash_client_identifier,
)


def test_client_identifier_hash_is_deterministic():
    first = hash_client_identifier(
        scope="login",
        client_identifier="192.0.2.10",
        secret="test-secret",
    )
    second = hash_client_identifier(
        scope="login",
        client_identifier="192.0.2.10",
        secret="test-secret",
    )

    assert first == second
    assert len(first) == 64
    assert "192.0.2.10" not in first


def test_client_identifier_hash_changes_with_scope():
    login_hash = hash_client_identifier(
        scope="login",
        client_identifier="192.0.2.10",
        secret="test-secret",
    )
    csrf_hash = hash_client_identifier(
        scope="csrf",
        client_identifier="192.0.2.10",
        secret="test-secret",
    )

    assert login_hash != csrf_hash


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0, "invalid"),
        (-1, "invalid"),
    ],
)
def test_window_rejects_invalid_duration(value, expected):
    now = datetime(2026, 11, 7, 10, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="positive"):
        calculate_window_start(now, value)


def test_window_requires_timezone_aware_timestamp():
    now = datetime(2026, 11, 7, 10, 0)

    with pytest.raises(ValueError, match="timezone-aware"):
        calculate_window_start(now, 60)


def test_window_is_aligned_to_utc():
    now = datetime(2026, 11, 7, 10, 2, 35, tzinfo=UTC)

    result = calculate_window_start(now, 60)

    assert result == datetime(2026, 11, 7, 10, 2, tzinfo=UTC)


class FakeResult:
    def __init__(self, count):
        self.count = count

    def scalar_one(self):
        return self.count


class FakeSession:
    def __init__(self, count):
        self.count = count
        self.executed_statement = None
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def execute(self, statement):
        self.executed_statement = statement
        return FakeResult(self.count)

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


def test_consume_rate_limit_allows_requests_within_limit():
    session = FakeSession(count=3)
    now = datetime(2026, 11, 7, 10, 0, 15, tzinfo=UTC)

    with patch(
        "identitybridge.infrastructure.rate_limit_service.SessionLocal",
        return_value=session,
    ):
        result = consume_rate_limit(
            scope="login",
            client_identifier="192.0.2.10",
            secret="test-secret",
            limit=5,
            window_seconds=60,
            now=now,
        )

    assert result == RateLimitDecision(
        allowed=True,
        count=3,
        retry_after=45,
    )
    assert session.committed
    assert session.closed
    assert not session.rolled_back


def test_consume_rate_limit_rejects_requests_over_limit():
    session = FakeSession(count=6)
    now = datetime(2026, 11, 7, 10, 0, 15, tzinfo=UTC)

    with patch(
        "identitybridge.infrastructure.rate_limit_service.SessionLocal",
        return_value=session,
    ):
        result = consume_rate_limit(
            scope="login",
            client_identifier="192.0.2.10",
            secret="test-secret",
            limit=5,
            window_seconds=60,
            now=now,
        )

    assert result.allowed is False
    assert result.count == 6
    assert result.retry_after == 45
    assert session.committed
    assert session.closed


def test_database_failure_rolls_back_and_closes_session():
    class FailingSession(FakeSession):
        def execute(self, statement):
            raise RuntimeError("database unavailable")

    session = FailingSession(count=0)

    with (
        patch(
            "identitybridge.infrastructure.rate_limit_service.SessionLocal",
            return_value=session,
        ),
        pytest.raises(RuntimeError, match="database unavailable"),
    ):
        consume_rate_limit(
            scope="login",
            client_identifier="192.0.2.10",
            secret="test-secret",
            limit=5,
            window_seconds=60,
        )

    assert session.rolled_back
    assert session.closed
    assert not session.committed


@pytest.mark.parametrize(
    ("scope", "identifier", "secret", "limit", "window"),
    [
        ("unknown", "192.0.2.10", "secret", 5, 60),
        ("login", "", "secret", 5, 60),
        ("login", "192.0.2.10", "", 5, 60),
        ("login", "192.0.2.10", "secret", 0, 60),
        ("login", "192.0.2.10", "secret", 5, 0),
    ],
)
def test_invalid_rate_limit_configuration_is_rejected(
    scope,
    identifier,
    secret,
    limit,
    window,
):
    with pytest.raises(ValueError):
        consume_rate_limit(
            scope=scope,
            client_identifier=identifier,
            secret=secret,
            limit=limit,
            window_seconds=window,
        )
