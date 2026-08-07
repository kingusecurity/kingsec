"""Add account_lockouts table (persists lockout state across restarts)

Revision ID: d73edff1fd7f
Revises: d8a8e784bc8e
Create Date: 2026-08-06 00:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d73edff1fd7f"
down_revision: str | None = "d8a8e784bc8e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "account_lockouts",
        sa.Column("user_id", sa.String(), primary_key=True),
        sa.Column("locked_until", sa.Float(), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("account_lockouts")
