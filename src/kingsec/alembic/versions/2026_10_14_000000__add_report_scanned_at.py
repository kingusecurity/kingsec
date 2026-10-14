"""add scanned_at to reports (nullable, no backfill)

Report "Scan Date" bug: the Assessment Information section and the cover
page's "Assessment Date" both stamped ``report.generated_at`` - the moment
the report was RENDERED - as the scan date. A report generated (or
regenerated) hours after the scan therefore dated the scan hours late
(proven live, 2026-10-14: a scan that ran 09:10-09:49 was stamped
13:50:56 because the PDF was rendered then).

Root cause was a persistence gap, not a template bug: the domain
``Report`` had no field for when the scan ran, so the templates had
nothing honest to render. ``reports.scanned_at`` records the scan time
(the assessment record is created seconds before scanning starts, so
``assessment.created_at`` is the scan time) as known at report
generation time.

NULL means "not recorded" - for rows persisted before this column
existed we genuinely cannot know the scan time from the report row
alone, and the templates fall back to ``generated_at`` for those rows.
Deliberately NO backfill: fabricating scan times for old rows would be
the same defect this migration exists to fix. NULL is the correct
historical value, same reasoning as the profile_id migration
(7545229e5084) - nullable needs no server_default.

IMPORTANT - ``downgrade()`` is NOT a rollback path (same standard as
the Phase 2A assessment_status, Phase 2C score_version, affected_asset,
and profile_id migrations). It only reverses the schema addition
(drops the column). No finding/verdict VALUE is lost - scanned_at is
purely additive metadata. But after ``downgrade()`` runs, downloaded
reports again stamp the render time as the scan date - silently
reintroducing the inconsistency this migration exists to fix. If this
migration needs to be undone, restore the database from a backup taken
before it ran; do not run ``alembic downgrade`` believing it reverses
that.

Revision ID: 9f3b7c1d2a84
Revises: 7545229e5084
Create Date: 2026-10-14 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9f3b7c1d2a84"
down_revision: str | None = "7545229e5084"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch_op:
        batch_op.add_column(sa.Column("scanned_at", sa.String(), nullable=True))


def downgrade() -> None:
    # NOT A ROLLBACK PATH - see the module docstring. Reverses only the
    # schema addition (drops the column); no report data is lost, but the
    # scan date in downloaded reports silently reverts to the render
    # time.
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_column("scanned_at")
