"""Add Attack Surface Management tables (Phase 19)

Revision ID: ccddeeff0011
Revises: aabbccddee00
Create Date: 2026-07-28 20:00:00.000000

"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "ccddeeff0011"
down_revision: Union[str, None] = "aabbccddee00"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "exposures",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), nullable=False),
        sa.Column("exposure_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False, server_default="medium"),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("detail_json", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("source", sa.String(), nullable=False, server_default="scanner"),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(), nullable=True),
        sa.Column("hostname", sa.String(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("url", sa.String(), nullable=True),
        sa.Column("tls_version", sa.String(), nullable=True),
        sa.Column("certificate_issuer", sa.String(), nullable=True),
        sa.Column("certificate_expiry", sa.String(), nullable=True),
        sa.Column("header_name", sa.String(), nullable=True),
        sa.Column("header_value", sa.String(), nullable=True),
        sa.Column("technology_name", sa.String(), nullable=True),
        sa.Column("technology_version", sa.String(), nullable=True),
        sa.Column("cloud_provider", sa.String(), nullable=True),
        sa.Column("cloud_bucket", sa.String(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.Column("first_seen", sa.String(), nullable=False),
        sa.Column("last_seen", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_exposures_asset_id", "exposures", ["asset_id"])
    op.create_index("ix_exposures_exposure_type", "exposures", ["exposure_type"])
    op.create_index("ix_exposures_severity", "exposures", ["severity"])
    op.create_index("ix_exposures_status", "exposures", ["status"])

    op.create_table(
        "exposure_history",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("exposure_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.Column("previous_value", sa.String(), nullable=True),
        sa.Column("new_value", sa.String(), nullable=True),
        sa.Column("actor", sa.String(), nullable=False, server_default="system"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_exposure_history_exposure_id", "exposure_history", ["exposure_id"])


def downgrade() -> None:
    op.drop_index("ix_exposure_history_exposure_id", table_name="exposure_history")
    op.drop_table("exposure_history")
    op.drop_index("ix_exposures_status", table_name="exposures")
    op.drop_index("ix_exposures_severity", table_name="exposures")
    op.drop_index("ix_exposures_exposure_type", table_name="exposures")
    op.drop_index("ix_exposures_asset_id", table_name="exposures")
    op.drop_table("exposures")
