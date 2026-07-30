"""Phase 24 — Create plugin_sdk_manifests table.

Revision ID: iijjkk001122
Revises: hhiijj001122
Create Date: 2026-07-29 04:00:00.000000
"""

from __future__ import annotations


import sqlalchemy as sa
from alembic import op

revision: str = "iijjkk001122"
down_revision: str | None = "hhiijj001122"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "plugin_sdk_manifests",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False, server_default="0.0.0"),
        sa.Column("author", sa.String(), nullable=False, server_default=""),
        sa.Column("website", sa.String(), nullable=False, server_default=""),
        sa.Column("license", sa.String(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("category", sa.String(), nullable=False, server_default="other"),
        sa.Column("entrypoint", sa.String(), nullable=False, server_default=""),
        sa.Column("minimum_kingsec_version", sa.String(), nullable=False, server_default="0.0.0"),
        sa.Column("permissions_json", sa.String(), nullable=True),
        sa.Column("dependencies_json", sa.String(), nullable=True),
        sa.Column("signature", sa.String(), nullable=False, server_default=""),
        sa.Column("installed", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("loaded", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("plugin_sdk_manifests")
