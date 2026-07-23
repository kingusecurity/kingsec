"""add revoked_tokens table

Revision ID: a1b2c3d4e5f6
Revises: 9ba138dca0e7
Create Date: 2026-07-22 02:50:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "cf73dd712190"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_index(op.f("ix_revoked_tokens_expires_at"), "revoked_tokens", ["expires_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_revoked_tokens_expires_at"), table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
