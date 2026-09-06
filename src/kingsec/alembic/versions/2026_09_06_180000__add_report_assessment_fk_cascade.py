"""add ON DELETE CASCADE foreign key from reports to assessments

KSEC-110-01: Phase 110's adversarial deletion testing found that
`reports.assessment_id` had no foreign-key relationship to
`assessments.id` at all (unlike `findings.assessment_id`, which already
has `ON DELETE CASCADE`) - deleting an Assessment that already had a
generated report left the report row permanently orphaned. This is inert
(no route can ever read an orphaned report back - GenerateReport always
re-fetches the live Assessment first, and 404s if it is gone), but it is
real, needless, permanent storage waste with no corresponding live record.

Safe to add here because `persist_report()` always upserts via
`session.merge()` (never DELETE-then-INSERT the way Assessment's own
`persist_assessment()` does), so this FK is never transiently violated by
a report's own save() - unlike `assessment_executions.assessment_id`
and `schedule_occurrences.assessment_id`, which are deliberately left
unconstrained for exactly that reason (see
2026_09_06_000000__add_assessment_executions.py's own docstring).

Any report rows already orphaned in an existing database (from before
this fix) are deleted first, since SQLite's batch-table-recreate (the
only way to add a FK to an existing column) would otherwise fail the
new constraint against that already-inconsistent data.

Revision ID: da4b78614806
Revises: 2b2a6432bfb8
Create Date: 2026-09-06 18:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "da4b78614806"
down_revision: str | None = "2b2a6432bfb8"
branch_labels: str | None = None
depends_on: str | None = None

_FK_NAME = "fk_reports_assessment_id_assessments"


def upgrade() -> None:
    # Remove any pre-existing orphaned report rows so the new FK
    # constraint doesn't fail against already-inconsistent data.
    op.execute("DELETE FROM reports WHERE assessment_id NOT IN (SELECT id FROM assessments)")

    with op.batch_alter_table("reports") as batch_op:
        batch_op.create_foreign_key(
            _FK_NAME,
            "assessments",
            ["assessment_id"],
            ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_constraint(_FK_NAME, type_="foreignkey")
