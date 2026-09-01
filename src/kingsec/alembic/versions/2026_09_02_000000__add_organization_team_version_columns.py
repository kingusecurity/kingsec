"""add optimistic-lock version column to organizations and teams

KSEC-86-01: SQLAlchemyOrganizationRepository.save()/.save_team() followed
the same read -> mutate -> blind-commit pattern identified for schedules in
KSEC-85-02: update_organization()/update_team() (adapters/inbound/web/
organization_routes.py) read the aggregate, mutate name/slug (or name/
description) in place, then call save()/save_team() unconditionally. Two
concurrent PATCH requests for the same organization/team could silently
clobber one another - no error, no conflict signal.

This adds a `version` counter, defaulted to 1 for every existing row, to
both `organizations` and `teams`. SQLAlchemyOrganizationRepository.save()/
.save_team() now scope their UPDATE to `WHERE id = ? AND version = ?` and
set `version = version + 1`; a write against a stale version matches zero
rows and raises OrganizationConflictError/TeamConflictError instead of
silently overwriting or being silently overwritten - the identical
mechanism already established for `schedules.version` (migration
de006efa9633).

Revision ID: 0fcacd6b048e
Revises: de006efa9633
Create Date: 2026-09-02 00:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "0fcacd6b048e"
down_revision: str | None = "de006efa9633"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.add_column(
        "teams",
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_column("teams", "version")
    op.drop_column("organizations", "version")
