"""add affected_asset to findings (nullable, no backfill)

Two report-quality defects, one schema change:

1. Asset attribution - every finding card in the generated report labels
   "Affected Asset" with the assessment-level target (e.g. the CIDR or
   hostname the operator typed), even when the scanner observed the finding
   on a *different, specific* host (nmap's per-host ``addr`` in a network
   scan, or the host IP behind a URL target's host sweep). A port finding
   on 192.168.1.5 was labelled as affecting "192.168.1.0/24".

2. Port severity - handled in code only (nmap_parser.py); no schema
   involved. Recorded here so the migration's purpose reads complete.

``findings.affected_asset`` stores the concrete host/asset the scanner
reported the finding on (IP or hostname string, as observed - never
fabricated). NULL means "the scanner reported no per-host asset", and
every reader treats NULL as "fall back to the assessment's target" -
the same honest fallback the report used before this column existed.

Deliberately NO backfill: there is no way to recover, after the fact,
which host a historical finding was observed on. Backfilling the
assessment target into this column would *look* precise while adding
zero information - worse, it would make "we don't know the specific
host" indistinguishable from "the scanner confirmed this host". NULL
preserves exactly the knowledge we actually have.

NULL is also why no server_default dance is needed (unlike
2026_09_14_000000's score_version backfill): the correct historical
value genuinely is "unknown", and the column default of NULL expresses
exactly that.

IMPORTANT - ``downgrade()`` is NOT a rollback path (same standard as the
Phase 2A assessment_status and Phase 2C score_version migrations). It
only reverses the schema addition (drops the column). No finding VALUE
is lost - affected_asset is purely additive metadata. But after
``downgrade()`` runs, pre-migration code reading these rows has never
heard of ``affected_asset`` and will render every finding card with the
assessment target again - silently reintroducing the mislabelling this
migration exists to fix. If this migration needs to be undone, restore
the database from a backup taken before it ran; do not run ``alembic
downgrade`` believing it reverses that.

Revision ID: 92f560c6414b
Revises: 289b5978e448
Create Date: 2026-10-04 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "92f560c6414b"
down_revision: str | None = "289b5978e448"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch_op:
        batch_op.add_column(sa.Column("affected_asset", sa.String(), nullable=True))


def downgrade() -> None:
    # NOT A ROLLBACK PATH - see the module docstring. Reverses only the
    # schema addition (drops the column); no finding data is lost, but the
    # per-finding asset distinction is gone and old code will mislabel
    # every finding card with the assessment target again.
    with op.batch_alter_table("findings") as batch_op:
        batch_op.drop_column("affected_asset")
