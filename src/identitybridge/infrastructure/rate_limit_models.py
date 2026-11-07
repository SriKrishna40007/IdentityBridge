from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from identitybridge.infrastructure.database import Base


class RateLimitCounter(Base):
    """Persistent fixed-window request counter."""

    __tablename__ = "rate_limit_counters"

    __table_args__ = (
        Index("ix_rate_limit_counters_window_start", "window_start"),
    )

    scope: Mapped[str] = mapped_column(
        String(32),
        primary_key=True,
    )

    client_hash: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )

    window_start: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        primary_key=True,
    )

    count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
