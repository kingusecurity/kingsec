"""Add AI Copilot tables (Phase 22)

Revision ID: gghhii001122
Revises: ffgghh001122
Create Date: 2026-07-29 20:00:00.000000

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "gghhii001122"
down_revision: Union[str, None] = "ffgghh001122"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "copilot_conversations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False, server_default="New Investigation"),
        sa.Column("assessment_id", sa.String(), nullable=True),
        sa.Column("finding_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("alert_id", sa.String(), nullable=True),
        sa.Column("exposure_id", sa.String(), nullable=True),
        sa.Column("messages_json", sa.String(), nullable=True),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_copilot_conversations_assessment_id", "copilot_conversations", ["assessment_id"])
    op.create_index("ix_copilot_conversations_finding_id", "copilot_conversations", ["finding_id"])
    op.create_index("ix_copilot_conversations_asset_id", "copilot_conversations", ["asset_id"])

    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("conversation_id", sa.String(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("author", sa.String(), nullable=False, server_default=""),
        sa.Column("pinned", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("assessment_id", sa.String(), nullable=True),
        sa.Column("finding_id", sa.String(), nullable=True),
        sa.Column("tags_json", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_investigation_notes_conversation_id", "investigation_notes", ["conversation_id"])
    op.create_index("ix_investigation_notes_assessment_id", "investigation_notes", ["assessment_id"])
    op.create_index("ix_investigation_notes_finding_id", "investigation_notes", ["finding_id"])


def downgrade() -> None:
    op.drop_table("investigation_notes")
    op.drop_table("copilot_conversations")
