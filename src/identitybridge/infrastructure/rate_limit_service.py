import hashlib
import hmac
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.dialects.postgresql import insert

from identitybridge.infrastructure.database import SessionLocal
from identitybridge.infrastructure.rate_limit_models import RateLimitCounter


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    count: int
    retry_after: int


def hash_client_identifier(
    *,
    scope: str,
    client_identifier: str,
    secret: str,
) -> str:
    """Return a keyed hash without persisting the raw client identifier."""
    if not scope or not client_identifier or not secret:
        raise ValueError("Scope, client identifier and secret are required")

    message = f"identitybridge:{scope}:{client_identifier}".encode()

    return hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def calculate_window_start(
    now: datetime,
    window_seconds: int,
) -> datetime:
    """Calculate the UTC-aligned start of a fixed rate-limit window."""
    if window_seconds < 1:
        raise ValueError("Window duration must be positive")

    if now.tzinfo is None:
        raise ValueError("Window timestamp must be timezone-aware")

    timestamp = now.astimezone(UTC).timestamp()
    window_timestamp = math.floor(timestamp / window_seconds) * window_seconds

    return datetime.fromtimestamp(window_timestamp, UTC)


def consume_rate_limit(
    *,
    scope: str,
    client_identifier: str,
    secret: str,
    limit: int,
    window_seconds: int,
    now: datetime | None = None,
) -> RateLimitDecision:
    """Atomically increment and evaluate a PostgreSQL fixed-window counter."""
    if scope not in {"login", "csrf"}:
        raise ValueError("Unsupported rate-limit scope")

    if limit < 1:
        raise ValueError("Rate limit must be positive")

    if window_seconds < 1:
        raise ValueError("Window duration must be positive")

    current_time = now or datetime.now(UTC)

    if current_time.tzinfo is None:
        raise ValueError("Current timestamp must be timezone-aware")

    current_time = current_time.astimezone(UTC)
    window_start = calculate_window_start(current_time, window_seconds)
    window_end = window_start + timedelta(seconds=window_seconds)

    client_hash = hash_client_identifier(
        scope=scope,
        client_identifier=client_identifier,
        secret=secret,
    )

    statement = (
        insert(RateLimitCounter)
        .values(
            scope=scope,
            client_hash=client_hash,
            window_start=window_start,
            count=1,
        )
        .on_conflict_do_update(
            index_elements=[
                RateLimitCounter.scope,
                RateLimitCounter.client_hash,
                RateLimitCounter.window_start,
            ],
            set_={"count": RateLimitCounter.count + 1},
        )
        .returning(RateLimitCounter.count)
    )

    db = SessionLocal()

    try:
        count = db.execute(statement).scalar_one()
        db.commit()

        retry_after = max(
            1,
            math.ceil((window_end - current_time).total_seconds()),
        )

        return RateLimitDecision(
            allowed=count <= limit,
            count=count,
            retry_after=retry_after,
        )

    except Exception:
        db.rollback()
        raise

    finally:
        db.close()
