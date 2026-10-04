"""add reports.assessment_status and backfill legacy scanner-status vocabulary

Phase 2A: ``ScannerRunSummary.status`` moved from a free-form ``str`` to
the ``ScannerRunState`` enum (PENDING/RUNNING/SUCCEEDED/FAILED/TIMED_OUT/
SKIPPED_INCOMPATIBLE/SKIPPED_BINARY_MISSING/SKIPPED_ASSET_MISSING), and
``Report`` gained an ``assessment_status`` field recording whether the
assessment it was generated from was COMPLETED or COMPLETED_WITH_GAPS.
Both changes need a real data migration, not just a schema change:
existing rows have the OLD status vocabulary ("pending", "completed",
"failed", "skipped") baked into their ``scanner_summary`` JSON blobs, and
existing ``reports`` rows have no ``assessment_status`` at all.

Two independent backfills:

1. ``reports.assessment_status`` (new column, default 'completed' for the
   ADD COLUMN itself so SQLite backfills every existing row atomically),
   then refined per-row: a report whose (already-backfilled)
   ``scanner_summary`` shows any scanner that didn't reach SUCCEEDED is
   re-labelled 'completed_with_gaps' - an honest, best-effort correction
   for historical reports rather than silently claiming full coverage
   they may not have had. Reports predating the scanner-coverage feature
   entirely (empty ``scanner_summary``) are left at 'completed', matching
   ``Report.assessment_status``'s own default for pre-existing callers.

2. The ``scanner_summary`` JSON blobs on BOTH ``assessments`` and
   ``reports`` - each entry's ``status`` string is remapped to the new
   vocabulary via the best-effort table below. This is necessarily lossy
   for "skipped": the old vocabulary had no concept of WHY a scanner was
   skipped, so every old "skipped" becomes SKIPPED_INCOMPATIBLE, the
   closest available meaning ("this scanner was not applicable"), not
   necessarily the true original reason.

Deliberately does NOT touch ``assessments.status`` itself (the
top-level lifecycle column) - retroactively reclassifying a historical
Assessment's own COMPLETED/FAILED verdict is a materially bigger claim
than relabelling its scanner-status vocabulary, and out of scope here.

``reports.assessment_id`` IS the real primary key (verified against the
live schema: ``PRIMARY KEY (assessment_id)``, and the sole write path -
``GenerateReport.execute()`` -> ``ReportRepository.save()`` ->
``persist_report()`` -> ``session.merge()`` - always upserts by that PK,
so two report rows for one assessment cannot exist; FIX 7's ``?format=``
query param only changes what ``download_report()`` renders on the fly
and never calls ``save()``). Keying both backfills on ``assessment_id``
is therefore safe.

``assessment_status``'s ``server_default='completed'`` exists ONLY to
backfill the ADD COLUMN atomically; it is dropped at the end of
``upgrade()``, once both backfills have run, via
``alter_column(..., server_default=None)``. Leaving a default on this
column permanently would mean any future insert path that omits
``assessment_status`` silently gets "completed" - full coverage claimed
by default - which is the exact Run #4 failure mode this phase exists to
eliminate, reproduced at the DB layer. Confirmed safe to drop: the sole
``ReportORM`` construction site (``mappers.report_to_orm()``) always sets
``assessment_status`` explicitly from the domain ``Report``, never relies
on the column default.

IMPORTANT - ``downgrade()`` is NOT a rollback path. It only reverses the
schema addition (drops the column). The ``scanner_summary`` vocabulary
backfill in step 2 is irreversible in practice: mapping "succeeded" back
to "completed" etc. cannot distinguish entries that were already
old-vocabulary before this migration ran from ones it just changed, so a
downgrade would be a guess, not a true inverse. Concretely: after
``downgrade()`` runs, ``scanner_summary`` blobs still contain the NEW
vocabulary ("succeeded", "skipped_incompatible", ...), which
pre-Phase-2A code cannot parse (its ``ScannerRunSummary.status`` expected
the old strings) - downgrading the schema does not restore
pre-Phase-2A-readable data. If this migration needs to be undone, restore
the database from a backup taken before it ran; do not run
``alembic downgrade`` believing it reverses the data change.

Revision ID: 64e10236c8c1
Revises: da4b78614806
Create Date: 2026-09-10 12:00:00.000000
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "64e10236c8c1"
down_revision: str | None = "da4b78614806"
branch_labels: str | None = None
depends_on: str | None = None

# Old (pre-Phase-2A) -> new ScannerRunState.value vocabulary. Only keys
# actually seen in production data are listed; anything else is left
# untouched (defensive - never guess at a value this migration doesn't
# recognise).
_STATUS_MAP: dict[str, str] = {
    "pending": "pending",
    "running": "running",
    "completed": "succeeded",
    "failed": "failed",
    "skipped": "skipped_incompatible",
}

_SUCCESS_VALUE = "succeeded"


def _backfill_scanner_summary(table_name: str, pk_col: str) -> None:
    conn = op.get_bind()
    rows = conn.execute(sa.text(f"SELECT {pk_col}, scanner_summary FROM {table_name}")).fetchall()  # noqa: S608  # nosec B608 — table_name/pk_col are hardcoded literals at the call sites below, never user input
    for pk, raw in rows:
        if not raw:
            continue
        entries = json.loads(raw)
        if not entries:
            continue
        changed = False
        for entry in entries:
            old_status = entry.get("status")
            new_status = _STATUS_MAP.get(old_status)
            if new_status is not None and new_status != old_status:
                entry["status"] = new_status
                changed = True
        if changed:
            conn.execute(
                sa.text(f"UPDATE {table_name} SET scanner_summary = :val WHERE {pk_col} = :pk"),  # noqa: S608  # nosec B608 — table_name/pk_col are hardcoded literals at the call sites below, never user input
                {"val": json.dumps(entries), "pk": pk},
            )


def _refine_report_assessment_status() -> None:
    """Re-label a report 'completed_with_gaps' if its backfilled
    scanner_summary shows any scanner that didn't reach SUCCEEDED."""
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT assessment_id, scanner_summary FROM reports")).fetchall()
    for assessment_id, raw in rows:
        if not raw:
            continue
        entries = json.loads(raw)
        if not entries:
            continue
        if any(entry.get("status") != _SUCCESS_VALUE for entry in entries):
            conn.execute(
                sa.text("UPDATE reports SET assessment_status = 'completed_with_gaps' WHERE assessment_id = :pk"),
                {"pk": assessment_id},
            )


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch_op:
        batch_op.add_column(
            sa.Column("assessment_status", sa.String(), nullable=False, server_default="completed")
        )

    _backfill_scanner_summary("assessments", "id")
    _backfill_scanner_summary("reports", "assessment_id")
    _refine_report_assessment_status()

    # Drop the default now that every existing row has been backfilled -
    # see the module docstring for why leaving it in place permanently
    # would be its own instance of the Run #4 false-assurance defect.
    with op.batch_alter_table("reports") as batch_op:
        batch_op.alter_column("assessment_status", server_default=None)


def downgrade() -> None:
    # NOT A ROLLBACK PATH. This only reverses the schema addition (drops
    # the column) - it does NOT undo the scanner_summary vocabulary
    # backfill, which is irreversible in practice (mapping "succeeded"
    # back to "completed" etc. cannot distinguish entries that were
    # already old-vocabulary before this migration from ones it just
    # changed). After this runs, scanner_summary blobs still contain the
    # NEW vocabulary, which pre-Phase-2A code cannot parse. If this
    # migration needs to be undone, restore the database from a backup
    # taken before it ran - do not run this believing it reverses the
    # data change.
    with op.batch_alter_table("reports") as batch_op:
        batch_op.drop_column("assessment_status")
