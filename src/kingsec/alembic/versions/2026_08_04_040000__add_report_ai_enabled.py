"""Add ai_enabled column to reports (AI-generated explanations feature)

Revision ID: 95032c918cb7
Revises: llmmnn001122
Create Date: 2026-08-04 04:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "95032c918cb7"
down_revision: str | None = "llmmnn001122"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column("ai_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("reports", "ai_enabled")
