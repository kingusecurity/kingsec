"""Add authorized_by and scope columns to reports (cover page metadata)

Revision ID: d8a8e784bc8e
Revises: a1ef92400984
Create Date: 2026-08-04 06:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "d8a8e784bc8e"
down_revision: str | None = "a1ef92400984"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("reports", sa.Column("authorized_by", sa.String(), nullable=False, server_default=""))
    op.add_column("reports", sa.Column("scope", sa.String(), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("reports", "scope")
    op.drop_column("reports", "authorized_by")
