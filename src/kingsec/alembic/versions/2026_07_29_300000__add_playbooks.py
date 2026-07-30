"""Phase 23 — Create playbooks and execution_history tables.

Revision ID: hhiijj001122
Revises: gghhii001122
Create Date: 2026-07-29 03:00:00.000000
"""

from __future__ import annotations


import sqlalchemy as sa
from alembic import op

revision: str = "hhiijj001122"
down_revision: str | None = "gghhii001122"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "playbooks",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("category", sa.String(), nullable=False, server_default="general"),
        sa.Column("severity", sa.String(), nullable=False, server_default="medium"),
        sa.Column("tags_json", sa.String(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("trigger_json", sa.String(), nullable=False, server_default="{}"),
        sa.Column("actions_json", sa.String(), nullable=False, server_default="[]"),
        sa.Column("rollback_actions_json", sa.String(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "execution_history",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("playbook_id", sa.String(), nullable=False),
        sa.Column("playbook_name", sa.String(), nullable=False, server_default=""),
        sa.Column("trigger_type", sa.String(), nullable=False, server_default="manual"),
        sa.Column("trigger_entity_id", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("action_logs_json", sa.String(), nullable=True),
        sa.Column("started_at", sa.String(), nullable=False),
        sa.Column("completed_at", sa.String(), nullable=True),
        sa.Column("duration_ms", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("rolled_back", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_execution_history_playbook_id",
        "execution_history",
        ["playbook_id"],
    )
    op.create_index(
        "ix_execution_history_status",
        "execution_history",
        ["status"],
    )
    op.create_index(
        "ix_execution_history_created",
        "execution_history",
        ["created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_execution_history_created", table_name="execution_history")
    op.drop_index("ix_execution_history_status", table_name="execution_history")
    op.drop_index("ix_execution_history_playbook_id", table_name="execution_history")
    op.drop_table("execution_history")
    op.drop_table("playbooks")
