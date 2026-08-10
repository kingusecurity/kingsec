"""Add ai_provider_config table

Revision ID: c4d2f8b9e1a3
Revises: b3c1e9a4f2d7
Create Date: 2026-08-09 20:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4d2f8b9e1a3"
down_revision: str | None = "b3c1e9a4f2d7"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ai_provider_config",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("api_key_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("model", sa.String(), nullable=True),
        sa.Column("base_url", sa.String(), nullable=True),
        sa.Column("updated_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ai_provider_config")
