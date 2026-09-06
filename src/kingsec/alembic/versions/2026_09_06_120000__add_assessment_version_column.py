"""add optimistic-lock version column to assessments

KSEC-107-01 / KSEC-108-01: Phase 107 discovered and deterministically
reproduced a lost-update race - two legitimately authorized
SubmitAssessment callers could both read the same AUTHORIZED assessment,
both transition their in-memory copies to RUNNING, and a stale earlier
copy's unconditional DELETE-then-INSERT (_operations.persist_assessment())
could silently overwrite a newer, real, terminal Assessment state (e.g.
COMPLETED with real findings) back to a stale RUNNING with no findings,
even though the execution ledger correctly still showed SUCCEEDED.

This adds a `version` counter, defaulted to 1 for every existing row -
the same idiom already proven on `schedules.version` (KSEC-85-02,
de006efa9633) and `organizations.version`/`teams.version` (KSEC-86-01).
persist_assessment() now scopes its replace to a conditional
`DELETE ... WHERE id = ? AND version = ?` and inserts the new row at
`version + 1`; a write against a stale version matches zero rows and
raises AssessmentConflictError instead of silently overwriting or being
silently overwritten.

Revision ID: 2b2a6432bfb8
Revises: 22fe86d6702f
Create Date: 2026-09-06 12:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "2b2a6432bfb8"
down_revision: str | None = "22fe86d6702f"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "assessments",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("assessments", "version")
