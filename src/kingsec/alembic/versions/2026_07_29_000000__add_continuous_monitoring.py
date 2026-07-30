"""Add Continuous Monitoring tables (Phase 20)

Revision ID: eeffgg001122
Revises: ccddeeff0011
Create Date: 2026-07-29 00:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "eeffgg001122"
down_revision: str | None = "ccddeeff0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "monitor_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("assessment_id", sa.String(), nullable=True),
        sa.Column("source", sa.String(), nullable=False, server_default="monitor"),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(), nullable=False, server_default="info"),
        sa.Column("context_json", sa.String(), nullable=True),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_monitor_events_event_type", "monitor_events", ["event_type"])
    op.create_index("ix_monitor_events_asset_id", "monitor_events", ["asset_id"])
    op.create_index("ix_monitor_events_timestamp", "monitor_events", ["timestamp"])

    op.create_table(
        "monitor_alerts",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("rule_id", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("severity", sa.String(), nullable=False, server_default="medium"),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("source_event_id", sa.String(), nullable=True),
        sa.Column("asset_id", sa.String(), nullable=True),
        sa.Column("assessment_id", sa.String(), nullable=True),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("acknowledged_at", sa.String(), nullable=True),
        sa.Column("resolved_at", sa.String(), nullable=True),
        sa.Column("acknowledged_by", sa.String(), nullable=True),
        sa.Column("resolved_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_monitor_alerts_rule_id", "monitor_alerts", ["rule_id"])
    op.create_index("ix_monitor_alerts_severity", "monitor_alerts", ["severity"])
    op.create_index("ix_monitor_alerts_status", "monitor_alerts", ["status"])

    op.create_table(
        "monitor_rules",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False, server_default=""),
        sa.Column("event_type", sa.String(), nullable=True),
        sa.Column("conditions_json", sa.String(), nullable=True),
        sa.Column("alert_severity", sa.String(), nullable=False, server_default="medium"),
        sa.Column("alert_title_template", sa.String(), nullable=False, server_default=""),
        sa.Column("alert_description_template", sa.String(), nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("cooldown_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("notify_channels_json", sa.String(), nullable=True),
        sa.Column("metadata_json", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_monitor_rules_event_type", "monitor_rules", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_monitor_rules_event_type", table_name="monitor_rules")
    op.drop_table("monitor_rules")
    op.drop_index("ix_monitor_alerts_status", table_name="monitor_alerts")
    op.drop_index("ix_monitor_alerts_severity", table_name="monitor_alerts")
    op.drop_index("ix_monitor_alerts_rule_id", table_name="monitor_alerts")
    op.drop_table("monitor_alerts")
    op.drop_index("ix_monitor_events_timestamp", table_name="monitor_events")
    op.drop_index("ix_monitor_events_asset_id", table_name="monitor_events")
    op.drop_index("ix_monitor_events_event_type", table_name="monitor_events")
    op.drop_table("monitor_events")
