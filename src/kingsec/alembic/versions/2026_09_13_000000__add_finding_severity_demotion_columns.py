"""add severity demotion columns to findings

Phase 2B-c Priority 1b: ffuf/gobuster's severity classifier previously
scored purely from URL path/status code, so a generic catch-all page at
/.env scored identically to a real leaked credentials file. The classifier
now demotes severity when the response content contradicts the path-based
guess (content-type mismatch, or a response shape shared across most of the
batch's otherwise-interesting hits) - but a downgrade nobody can see or
audit is its own honesty problem, so it must be recorded, not silent.

`original_severity` and `demotion_reason` are both NULL for every existing
row and for any finding that was never demoted - no backfill needed, NULL
already means exactly "not demoted" for rows written before this feature
existed.

Revision ID: 5db990f46ee0
Revises: 64e10236c8c1
Create Date: 2026-09-13 00:00:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5db990f46ee0"
down_revision: str | None = "64e10236c8c1"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("original_severity", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("demotion_reason", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "demotion_reason")
    op.drop_column("findings", "original_severity")
