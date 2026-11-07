"""create rate limit counters

Revision ID: 7b3f2a91c640
Revises: 2acd6e5e1f34
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7b3f2a91c640"
down_revision: str | Sequence[str] | None = "2acd6e5e1f34"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rate_limit_counters",
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("client_hash", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint(
            "scope",
            "client_hash",
            "window_start",
            name="pk_rate_limit_counters",
        ),
    )

    op.create_index(
        "ix_rate_limit_counters_window_start",
        "rate_limit_counters",
        ["window_start"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_rate_limit_counters_window_start",
        table_name="rate_limit_counters",
    )
    op.drop_table("rate_limit_counters")
