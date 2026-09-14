"""add score_version to reports, backfill existing rows to v1

Phase 2C Step 2: ``compute_executive_score()`` (the report's 0-100 risk
score) was replaced with a bounded, strictly-monotonic multiplicative
retention model ("v2") - the old linear-deduction formula saturated to 0
on realistic finding counts (docs/E2E-EVIDENCE-PHASE2B.md, Phase 2C Step 1
calibration report). The old formula is kept, renamed to
compute_executive_score_v1() and marked deprecated, specifically so
historical reports stay reproducible forever rather than being silently
rescored under a formula that didn't exist when they were generated.

That guarantee needs a real recorded fact per row, not an assumption:
every report persisted before this migration was scored under the OLD
(now "v1") formula, and every report from now on is scored under "v2".
``reports.score_version`` records which one, so ``Report.executive_score``
(domain/report.py) and the report-list projection
(infrastructure/persistence/repositories/report.py) can each replay the
correct formula for that specific row instead of guessing.

Same idiom as 2026_09_10_120000's own ``assessment_status`` backfill:
``server_default='v1'`` on the ADD COLUMN so SQLite backfills every
existing row atomically to the correct historical value, then the
server-side default is dropped once backfilled - leaving a default in
place permanently would mean any future insert path that omits
score_version silently gets "v1" at the DB layer, contradicting the
Python-side ORM default of "v2" and reintroducing exactly the kind of
silent-wrong-default defect class this project has hit before. Confirmed
safe to drop: the sole ``ReportORM`` construction site
(``mappers.report_to_orm()``) always sets ``score_version`` explicitly
from the domain ``Report``, never relies on the column default.

IMPORTANT - ``downgrade()`` is NOT a rollback path (same standard as the
Phase 2A ``assessment_status`` migration). It only reverses the schema
addition (drops the column); no score VALUE is lost. But the column's
entire purpose is letting code distinguish v1-scored rows from v2-scored
ones - after ``downgrade()`` runs, that distinction is gone, and pre-2C
code has never heard of ``score_version``. It will compute whichever
single formula it has against every row, including ones that were
actually scored under the OTHER formula - silently re-scoring historical
reports under a formula that never produced them. If this migration needs
to be undone, restore the database from a backup taken before it ran; do
not run ``alembic downgrade`` believing it reverses that.

Revision ID: 9601803f77a8
Revises: 5db990f46ee0
Create Date: 2026-09-14 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
# NOTE: an earlier draft of this file used the placeholder-looking id
# "a1b2c3d4e5f6" - a REAL collision with an existing revision already in
# this versions/ directory (2026_07_22_025000__add_revoked_tokens.py),
# caught by alembic itself ("Cycle is detected in revisions...") the
# first time this migration was actually run against a database. Caught
# before it was applied anywhere; replaced with a freshly generated,
# checked-unique id.
revision: str = "9601803f77a8"
down_revision: str | None = "5db990f46ee0"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch_op:
        batch_op.add_column(sa.Column("score_version", sa.String(), nullable=False, server_default="v1"))

    # Drop the default now that every existing row has been backfilled to
    # "v1" - see the module docstring for why leaving it in place
    # permanently would be its own instance of a silent-wrong-default
    # defect (the application's ORM default is "v2"; a lingering DB-level
    # default of "v1" would contradict it for any insert path that omits
    # the field, instead of failing loudly).
    with op.batch_alter_table("reports") as batch_op:
        batch_op.alter_column("score_version", server_default=None)


def downgrade() -> None:
    # NOT A ROLLBACK PATH - same standard as the Phase 2A assessment_status
    # migration. Reverses only the schema addition (drops the column); no
    # existing score VALUE is lost, since score_version is purely additive
    # metadata about which formula produced an already-persisted score.
    #
    # But the column's whole PURPOSE is to let code tell v1-scored rows
    # apart from v2-scored ones - after this runs, that distinction is
    # gone. Pre-2C code reading these rows has never heard of score_version
    # and will compute whichever formula it has (its own, single, current
    # one) against every row, including ones that were actually scored
    # under the other formula - silently re-scoring historical reports
    # under a formula that didn't produce them. If this migration needs to
    # be undone, restore the database from a backup taken before it ran;
    # do not run `alembic downgrade` believing it reverses that.
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_column("score_version")
