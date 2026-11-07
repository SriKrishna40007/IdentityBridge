import pytest

from identitybridge.infrastructure.rate_limit_service import RateLimitDecision


@pytest.fixture(autouse=True)
def isolate_rate_limit_database(monkeypatch):
    """Keep ordinary API tests independent of PostgreSQL rate-limit storage."""

    def allow_rate_limit(**kwargs):
        return RateLimitDecision(
            allowed=True,
            count=1,
            retry_after=60,
        )

    monkeypatch.setattr(
        "identitybridge.security.rate_limit.consume_rate_limit",
        allow_rate_limit,
    )
