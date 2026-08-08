"""Add profile_id and scanner_summary to assessments; scanner_summary to reports

Revision ID: 7f85c87712a1
Revises: d73edff1fd7f
Create Date: 2026-08-08 00:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7f85c87712a1"
down_revision: str | None = "d73edff1fd7f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("assessments", sa.Column("profile_id", sa.String(), nullable=True))
    op.add_column(
        "assessments",
        sa.Column("scanner_summary", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "reports",
        sa.Column("scanner_summary", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("reports", "scanner_summary")
    op.drop_column("assessments", "scanner_summary")
    op.drop_column("assessments", "profile_id")
