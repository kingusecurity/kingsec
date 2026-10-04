"""add profile_id to reports (nullable, no backfill)

Report Methodology bug: an assessment launched with the ``quick-scan``
profile rendered its downloaded report with "This assessment did not use
a pre-configured profile", contradicting the assessment's own
``profile_id``.

Root cause was a persistence gap, not a template bug:
``Report.from_assessment()`` correctly carried ``profile_id`` from the
live ``Assessment`` into the domain ``Report``, but
``report_to_orm()`` had nowhere to store it (``reports`` had no such
column) and ``report_to_domain()`` therefore rebuilt every stored
report with ``profile_id=None``. The generate-report endpoint renders
from the fresh domain object (correct), but the download endpoint
re-renders from the stored row - so every downloaded report lost the
profile line.

``reports.profile_id`` records the profile the assessment ran under, as
known at report generation time. NULL means "not recorded" - for rows
persisted before this column existed we genuinely cannot know whether
a profile was configured, and the template's existing NULL branch
("did not use a pre-configured profile") is the honest rendering for
those rows. Deliberately NO backfill: guessing ``quick-scan`` for old
rows would fabricate a fact the system never recorded. NULL is the
correct historical value, same reasoning as the affected_asset
migration (92f560c6414b) - nullable needs no server_default.

IMPORTANT - ``downgrade()`` is NOT a rollback path (same standard as
the Phase 2A assessment_status, Phase 2C score_version, and
affected_asset migrations). It only reverses the schema addition
(drops the column). No finding/verdict VALUE is lost - profile_id is
purely additive metadata. But after ``downgrade()`` runs, downloaded
reports again render the "no pre-configured profile" line even for
assessments that used one - silently reintroducing the inconsistency
this migration exists to fix. If this migration needs to be undone,
restore the database from a backup taken before it ran; do not run
``alembic downgrade`` believing it reverses that.

Revision ID: 7545229e5084
Revises: 92f560c6414b
Create Date: 2026-10-04 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7545229e5084"
down_revision: str | None = "92f560c6414b"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch_op:
        batch_op.add_column(sa.Column("profile_id", sa.String(), nullable=True))


def downgrade() -> None:
    # NOT A ROLLBACK PATH - see the module docstring. Reverses only the
    # schema addition (drops the column); no report data is lost, but the
    # profile line in downloaded reports silently reverts to the
    # "no pre-configured profile" wording.
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_column("profile_id")
