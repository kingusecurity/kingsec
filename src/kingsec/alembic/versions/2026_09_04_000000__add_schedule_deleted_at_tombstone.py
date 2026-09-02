"""add deleted_at tombstone column to schedules

KSEC-88-03: SqlAlchemyScheduleRepository.save() could not distinguish a
schedule id that never existed from one that existed at version 1 (never
yet updated) and was deleted by a concurrent delete_schedule() - a stale
write racing that exact delete could silently resurrect it, since a
physically-removed row leaves no trace to check against. The KSEC-87-03
mitigation (`version != 1`) only *inferred* this from the version the
stale caller happened to read; it could not detect the version-1 case at
all.

This closes the gap structurally instead of by inference: delete() now
sets `deleted_at` rather than removing the row (a tombstone), so save()
can tell "never existed" (no row) apart from "existed and was deleted"
(row present, deleted_at set) with certainty, regardless of version. Every
read path (find_by_id/find_by_user_id/find_all/find_due) filters
`WHERE deleted_at IS NULL`, so a tombstoned row stays invisible everywhere
else - behaviorally identical to the old hard delete for every caller
except save()'s own existence check.

Revision ID: d72bbb65a1aa
Revises: b61ad7b141a0
Create Date: 2026-09-04 00:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "d72bbb65a1aa"
down_revision: str | None = "b61ad7b141a0"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("schedules", sa.Column("deleted_at", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("schedules", "deleted_at")
