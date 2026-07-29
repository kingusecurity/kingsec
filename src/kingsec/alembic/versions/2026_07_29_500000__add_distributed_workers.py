"""Add distributed worker, job queue, lease, and dead letter tables.

Phase 25 — Distributed Scan Workers & Job Queue.

Revision ID: jjkkll001122
Revises: iijjkk001122
Create Date: 2026-07-29 05:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

import sqlalchemy as sa
from alembic import op

revision: str = "jjkkll001122"
down_revision: str | None = "iijjkk001122"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workers",
        sa.Column("worker_id", sa.String(), nullable=False),
        sa.Column("hostname", sa.String(), nullable=False),
        sa.Column("os", sa.String(), nullable=False, server_default=""),
        sa.Column("cpu", sa.String(), nullable=False, server_default=""),
        sa.Column("ram_mb", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("capabilities_json", sa.String(), nullable=True),
        sa.Column("current_jobs_json", sa.String(), nullable=True),
        sa.Column("health", sa.String(), nullable=False, server_default="healthy"),
        sa.Column("last_heartbeat", sa.String(), nullable=False, server_default=""),
        sa.Column("status", sa.String(), nullable=False, server_default="online"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("worker_id"),
    )
    op.create_index("ix_workers_status", "workers", ["status"])

    op.create_table(
        "job_queue_entries",
        sa.Column("entry_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False, server_default="queued"),
        sa.Column("payload", sa.Text(), nullable=False, server_default=""),
        sa.Column("target", sa.String(), nullable=False, server_default=""),
        sa.Column("scanner_ids_json", sa.String(), nullable=True),
        sa.Column("assigned_worker_id", sa.String(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_retries", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("error_message", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("started_at", sa.String(), nullable=True),
        sa.Column("completed_at", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("entry_id"),
    )
    op.create_index("ix_job_queue_job_id", "job_queue_entries", ["job_id"])
    op.create_index("ix_job_queue_state", "job_queue_entries", ["state"])
    op.create_index("ix_job_queue_target", "job_queue_entries", ["target"])
    op.create_index("ix_job_queue_worker", "job_queue_entries", ["assigned_worker_id"])

    op.create_table(
        "job_leases",
        sa.Column("lease_id", sa.String(), nullable=False),
        sa.Column("job_id", sa.String(), nullable=False),
        sa.Column("worker_id", sa.String(), nullable=False),
        sa.Column("acquired_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
        sa.Column("renewed_at", sa.String(), nullable=False, server_default=""),
        sa.Column("released_at", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("lease_id"),
        sa.UniqueConstraint("job_id"),
    )
    op.create_index("ix_job_leases_worker", "job_leases", ["worker_id"])

    op.create_table(
        "dead_letter_entries",
        sa.Column("entry_id", sa.String(), nullable=False),
        sa.Column("original_job_id", sa.String(), nullable=False),
        sa.Column("original_entry_id", sa.String(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column("payload", sa.Text(), nullable=False, server_default=""),
        sa.Column("target", sa.String(), nullable=False, server_default=""),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed_at", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("entry_id"),
    )
    op.create_index("ix_dead_letter_job", "dead_letter_entries", ["original_job_id"])


def downgrade() -> None:
    op.drop_table("dead_letter_entries")
    op.drop_table("job_leases")
    op.drop_table("job_queue_entries")
    op.drop_table("workers")
