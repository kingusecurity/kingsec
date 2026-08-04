"""Add history column to reports (risk-over-time chart)

Revision ID: a1ef92400984
Revises: 95032c918cb7
Create Date: 2026-08-04 05:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a1ef92400984"
down_revision: str | None = "95032c918cb7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column("history", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("reports", "history")
