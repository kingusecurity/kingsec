"""add schedule_occurrences table and assessments.schedule_occurrence_id

KSEC-98-01: Phase 93's try_claim() guarantees only one scheduler *instance*
processes a given due schedule at a time, but does not prevent the same
logical occurrence (a schedule's next_run being fulfilled) from producing
two independent real assessments if a submission succeeds while the
schedule's own finalization write later fails (Phase 94/96) - the schedule
stays due and a later poll cycle reprocesses the identical occurrence.

This adds a second, independent, database-enforced protection: each
occurrence's identity is (schedule_id, occurrence_key), unique-indexed so
the database itself is the final concurrency arbiter, not an
application-level "check then insert". See
application/schedule_occurrence.py for the CLAIMED -> ASSESSMENT_CREATED ->
SUBMITTED state machine this table stores, and
application/use_cases/submit_scheduled_assessment.py for the orchestrator
that drives it.

`assessments.schedule_occurrence_id` is a single, nullable FK - NULL for
every manually-created assessment - letting an assessment produced by a
scheduled occurrence be traced back to (occurrence -> schedule) via one
join, without duplicating schedule_id/owner_user_id onto the assessments
table itself.

Revision ID: 6984c15bfb36
Revises: d72bbb65a1aa
Create Date: 2026-09-05 00:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "6984c15bfb36"
down_revision: str | None = "d72bbb65a1aa"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "schedule_occurrences",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("schedule_id", sa.String(), sa.ForeignKey("schedules.id"), nullable=False),
        sa.Column("occurrence_key", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("assessment_id", sa.String(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("claimed_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
    )
    op.create_index(
        "ix_schedule_occurrences_schedule_occurrence_unique",
        "schedule_occurrences",
        ["schedule_id", "occurrence_key"],
        unique=True,
    )
    # SQLite cannot ALTER a table to add a column carrying a new FK
    # constraint in one step (no ALTER-of-constraints support) - batch
    # mode performs the standard SQLite copy-and-move instead.
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.add_column(sa.Column("schedule_occurrence_id", sa.String(), nullable=True))
        batch_op.create_foreign_key(
            "fk_assessments_schedule_occurrence_id",
            "schedule_occurrences",
            ["schedule_occurrence_id"],
            ["id"],
        )


def downgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.drop_constraint("fk_assessments_schedule_occurrence_id", type_="foreignkey")
        batch_op.drop_column("schedule_occurrence_id")
    op.drop_index("ix_schedule_occurrences_schedule_occurrence_unique", table_name="schedule_occurrences")
    op.drop_table("schedule_occurrences")
