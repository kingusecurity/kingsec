"""add assessment_executions table

KSEC-102-01: durable ledger for one assessment's execution attempt.

Phase 99 proved a real, unclean process termination between
SubmitAssessment.execute() returning and ThreadJobRunner's background
thread finishing leaves no durable trace of whether the scan actually
started, ran, or finished. Phase 101 designed the smallest durable ledger
that could close that visibility gap; this migration creates it.

`assessment_id` is the execution identity - UNIQUE-indexed so the
database, not application code, is the concurrency arbiter (the same
convention already established by schedule_occurrences in
6984c15bfb36). `id` is a separate, opaque surrogate primary key, matching
ScheduleOccurrenceORM's own convention.

`assessment_id` is deliberately NOT a foreign key to assessments.id:
_operations.persist_assessment() does a DELETE-then-INSERT of the
assessments row on every save() (full aggregate replace), so a FK pointing
at assessments.id would fail with a real FOREIGN KEY constraint error the
next time an assessment with a linked execution record is saved (with
PRAGMA foreign_keys=ON, as production uses) - proven empirically during
development. schedule_occurrences.assessment_id (6984c15bfb36) is
similarly unconstrained for the same reason.

See application/assessment_execution_ledger.py for the
REQUESTED -> CLAIMED -> RUNNING -> {SUCCEEDED, FAILED} state machine this
table stores, and application/ports/outbound/assessment_execution_repository.py
for the atomic, version+status-gated transitions that enforce it.

Revision ID: 22fe86d6702f
Revises: 6984c15bfb36
Create Date: 2026-09-06 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "22fe86d6702f"
down_revision: str | None = "6984c15bfb36"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "assessment_executions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("assessment_id", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
    )
    op.create_index(
        "ix_assessment_executions_assessment_id_unique",
        "assessment_executions",
        ["assessment_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_assessment_executions_assessment_id_unique", table_name="assessment_executions")
    op.drop_table("assessment_executions")
