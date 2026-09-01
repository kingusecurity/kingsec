"""add optimistic-lock version column to schedules

KSEC-85-02: every schedule mutation use case (pause/resume/update/enable/
disable/trigger) and the in-process scheduler's own due-schedule handling
(infrastructure/scheduler/in_process_scheduler.py) followed the same
pattern: read the complete ScanSchedule, mutate a local copy, then blind
full-record save() with no concurrency check. Two callers reading the same
row and saving concurrently silently lose whichever write happened first -
no error, no conflict signal, no audit trail of the clobbered change.

This adds a `version` counter, defaulted to 1 for every existing row.
SqlAlchemyScheduleRepository.save() now scopes its UPDATE to
`WHERE id = ? AND version = ?` and sets `version = version + 1`; a write
against a stale version matches zero rows and raises ScheduleConflictError
instead of silently overwriting or being silently overwritten.

Revision ID: de006efa9633
Revises: a3f7c9d2e8b1
Create Date: 2026-09-01 01:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "de006efa9633"
down_revision: str | None = "a3f7c9d2e8b1"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "schedules",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("schedules", "version")
