"""Add cve_ids, cwe_ids, cvss_score, cvss_vector to findings

Revision ID: b3c1e9a4f2d7
Revises: 7f85c87712a1
Create Date: 2026-08-09 18:00:00.000000

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3c1e9a4f2d7"
down_revision: str | None = "7f85c87712a1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("cve_ids", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("cwe_ids", sa.String(), nullable=True))
    op.add_column("findings", sa.Column("cvss_score", sa.Float(), nullable=True))
    op.add_column("findings", sa.Column("cvss_vector", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "cvss_vector")
    op.drop_column("findings", "cvss_score")
    op.drop_column("findings", "cwe_ids")
    op.drop_column("findings", "cve_ids")
