"""extend assets table and create asset inventory tables

Revision ID: aabbccddee00
Revises: f4361120c9bf
Create Date: 2026-07-28 19:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic import op
import sqlalchemy as sa


if TYPE_CHECKING:
    pass


revision: str = "aabbccddee00"
down_revision: str | None = "f4361120c9bf"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # -- Add columns to existing "assets" table -------------------------------
    with op.batch_alter_table("assets") as batch_op:
        batch_op.add_column(sa.Column("asset_type", sa.String(), nullable=False, server_default="host"))
        batch_op.add_column(sa.Column("domain", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("fqdn", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("mac_address", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("os_version", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("location", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("description", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("open_ports", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("certificate_issuer", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("certificate_expiry", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("tls_version", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("cloud_provider", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("cloud_region", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("container_runtime", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("container_image", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("database_type", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("database_version", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("web_server", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("programming_language", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("framework", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("cms", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("first_seen", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("last_seen", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"))
        batch_op.add_column(sa.Column("metadata_json", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("updated_at", sa.String(), nullable=True))
        batch_op.create_index("ix_assets_domain", ["domain"], unique=False)

    # -- Create new tables ----------------------------------------------------
    op.create_table(
        "asset_tags",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.String(), nullable=False, index=True),
        sa.Column("key", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_tags_asset_id", "asset_tags", ["asset_id"])

    op.create_table(
        "asset_technologies",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.String(), nullable=False, index=True),
        sa.Column("technology_type", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=True),
        sa.Column("vendor", sa.String(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_technologies_asset_id", "asset_technologies", ["asset_id"])

    op.create_table(
        "asset_relationships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_asset_id", sa.String(), nullable=False, index=True),
        sa.Column("target_asset_id", sa.String(), nullable=False, index=True),
        sa.Column("relationship_type", sa.String(), nullable=False),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["source_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_relationships_source", "asset_relationships", ["source_asset_id"])
    op.create_index("ix_asset_relationships_target", "asset_relationships", ["target_asset_id"])

    op.create_table(
        "asset_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("asset_id", sa.String(), nullable=False, index=True),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("previous_value", sa.String(), nullable=True),
        sa.Column("new_value", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False, server_default="system"),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_asset_history_asset_id", "asset_history", ["asset_id"])
    op.create_index("ix_asset_history_timestamp", "asset_history", ["timestamp"])


def downgrade() -> None:
    op.drop_table("asset_history")
    op.drop_table("asset_relationships")
    op.drop_table("asset_technologies")
    op.drop_table("asset_tags")

    with op.batch_alter_table("assets") as batch_op:
        batch_op.drop_index("ix_assets_domain")
        batch_op.drop_column("updated_at")
        batch_op.drop_column("metadata_json")
        batch_op.drop_column("risk_score")
        batch_op.drop_column("last_seen")
        batch_op.drop_column("first_seen")
        batch_op.drop_column("cms")
        batch_op.drop_column("framework")
        batch_op.drop_column("programming_language")
        batch_op.drop_column("web_server")
        batch_op.drop_column("database_version")
        batch_op.drop_column("database_type")
        batch_op.drop_column("container_image")
        batch_op.drop_column("container_runtime")
        batch_op.drop_column("cloud_region")
        batch_op.drop_column("cloud_provider")
        batch_op.drop_column("tls_version")
        batch_op.drop_column("certificate_expiry")
        batch_op.drop_column("certificate_issuer")
        batch_op.drop_column("open_ports")
        batch_op.drop_column("description")
        batch_op.drop_column("location")
        batch_op.drop_column("os_version")
        batch_op.drop_column("mac_address")
        batch_op.drop_column("fqdn")
        batch_op.drop_column("domain")
        batch_op.drop_column("asset_type")
