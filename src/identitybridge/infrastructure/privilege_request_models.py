from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from identitybridge.infrastructure.database import Base


class PrivilegeRequest(Base):
    """Track the lifecycle of a just-in-time privileged access request."""

    __tablename__ = "privilege_requests"

    __table_args__ = (
        CheckConstraint(
            "status IN ("
            "'pending', 'approved', 'rejected', "
            "'grant_pending', 'grant_failed', 'active', "
            "'revoke_pending', 'revoke_failed', 'expired', 'revoked'"
            ")",
            name="ck_privilege_requests_status",
        ),
        CheckConstraint(
            "requested_duration_minutes BETWEEN 1 AND 480",
            name="ck_privilege_requests_duration",
        ),
        CheckConstraint(
            "retry_count >= 0",
            name="ck_privilege_requests_retry_count",
        ),
        Index("ix_privilege_requests_status", "status"),
        Index("ix_privilege_requests_target_user_id", "target_user_id"),
        Index("ix_privilege_requests_requester_sub", "requester_sub"),
        Index("ix_privilege_requests_expires_at", "expires_at"),
        Index("ix_privilege_requests_next_retry_at", "next_retry_at"),
    )

    id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )

    requester_sub: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    target_user_id: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    role_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    justification: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default="pending",
    )

    approver_sub: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    decision_comment: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    requested_duration_minutes: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=lambda: datetime.now(UTC),
    )

    approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revocation_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # None means the original Keycloak role state has not yet been checked.
    role_preexisting: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    # True only when this workflow successfully created the role assignment.
    grant_applied: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="false",
    )

    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )
