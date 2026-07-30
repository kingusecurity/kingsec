"""Add Threat Intelligence tables (Phase 21)

Revision ID: ffgghh001122
Revises: eeffgg001122
Create Date: 2026-07-29 10:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "ffgghh001122"
down_revision: str | None = "eeffgg001122"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cve_entries",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("cve_code", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(), nullable=False, server_default="NONE"),
        sa.Column("published_date", sa.String(), nullable=True),
        sa.Column("last_modified", sa.String(), nullable=True),
        sa.Column("cvss_data_json", sa.String(), nullable=True),
        sa.Column("epss_data_json", sa.String(), nullable=True),
        sa.Column("exploit_maturity", sa.String(), nullable=False, server_default="unknown"),
        sa.Column("affected_products_json", sa.String(), nullable=True),
        sa.Column("references_json", sa.String(), nullable=True),
        sa.Column("vendor_advisories_json", sa.String(), nullable=True),
        sa.Column("weaknesses_json", sa.String(), nullable=True),
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("kev_entry_json", sa.String(), nullable=True),
        sa.Column("threat_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("exploitability_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("priority_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_code"),
    )
    op.create_index("ix_cve_entries_cve_code", "cve_entries", ["cve_code"])
    op.create_index("ix_cve_entries_severity", "cve_entries", ["severity"])
    op.create_index("ix_cve_entries_is_kev", "cve_entries", ["is_kev"])
    op.create_index("ix_cve_entries_threat_score", "cve_entries", ["threat_score"])

    op.create_table(
        "threat_feeds",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("feed_type", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("source_url", sa.String(), nullable=False, server_default=""),
        sa.Column("entries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_synced", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_feeds_feed_type", "threat_feeds", ["feed_type"])


def downgrade() -> None:
    op.drop_table("threat_feeds")
    op.drop_table("cve_entries")
