"""Add issued_at to licenses

Revision ID: d1e2f3a4b5c6
Revises: c4d2f8b9e1a3
Create Date: 2026-08-10 05:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d1e2f3a4b5c6"
down_revision: str | None = "c4d2f8b9e1a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "licenses",
        sa.Column("issued_at", sa.String(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("licenses", "issued_at")
