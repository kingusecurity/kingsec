"""Add owner column to copilot_conversations (access control)

Revision ID: llmmnn001122
Revises: kkllmm001122
Create Date: 2026-08-01 21:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "llmmnn001122"
down_revision: str | None = "kkllmm001122"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("copilot_conversations", sa.Column("owner", sa.String(), nullable=True))
    op.create_index("ix_copilot_conversations_owner", "copilot_conversations", ["owner"])


def downgrade() -> None:
    op.drop_index("ix_copilot_conversations_owner", table_name="copilot_conversations")
    op.drop_column("copilot_conversations", "owner")
