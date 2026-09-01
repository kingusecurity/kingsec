"""add assessment_concurrency_slots table for max_concurrent_assessments

KSEC-87-02: `max_concurrent_assessments` existed as configuration
(infrastructure/config/models.py) but was never enforced anywhere in the
codebase - confirmed by a repo-wide search finding zero references to it
outside its own Field() declaration. Enforcing it safely requires an
atomic check-and-claim, not a "count running, then start if under the
limit" read-then-write (which two concurrent requests could both pass,
recreating the exact TOCTOU class Phases 85/86 closed for schedules and
organizations/teams).

This adds a dedicated single-row counter table. Every claim/release is a
single conditional UPDATE (`WHERE active_count < :max` / `> 0`), so the
capacity check and the write happen as one atomic database statement -
see infrastructure/persistence/repositories/assessment_concurrency.py.
This is deliberately a SEPARATE table from `assessments`, not a column on
it: it counts across all assessment rows at once, a different kind of
constraint than the per-row optimistic-lock `version` columns already
used for schedules/organizations/teams.

Revision ID: b61ad7b141a0
Revises: 0fcacd6b048e
Create Date: 2026-09-03 00:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "b61ad7b141a0"
down_revision: str | None = "0fcacd6b048e"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "assessment_concurrency_slots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("active_count", sa.Integer(), nullable=False, server_default="0"),
    )
    # Exactly one row ever exists (id=1) - seeded here so the very first
    # try_reserve_slot() call has a row to conditionally UPDATE against.
    op.execute("INSERT INTO assessment_concurrency_slots (id, active_count) VALUES (1, 0)")


def downgrade() -> None:
    op.drop_table("assessment_concurrency_slots")
