"""add unique constraints on organization/team memberships

KSEC-84-01: organization_memberships/team_memberships had no uniqueness
guard on (user_id, organization_id)/(user_id, team_id). add_member()/
add_team_member() (infrastructure/persistence/repositories/organization.py)
each did a separate SELECT-then-INSERT with no DB-level backstop, so two
concurrent "add this member" requests for the same user could both insert -
not just a duplicate row, but a live crash: get_member_role() (the
pervasive authorization gate for every organization/team route) uses
scalar_one_or_none(), which raises MultipleResultsFound once a duplicate
exists, turning every subsequent authorization check for that user in that
org into an unhandled 500 until an operator manually deletes the extra row.

Existing duplicates (if any) are removed first, keeping the earliest row
(lowest autoincrement id) per (user_id, organization_id) / (user_id,
team_id) pair, before the unique index is created - otherwise the
CREATE UNIQUE INDEX itself would fail on any database that already has a
duplicate.

Revision ID: a3f7c9d2e8b1
Revises: 91969658a556
Create Date: 2026-09-01 00:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "a3f7c9d2e8b1"
down_revision: str | None = "91969658a556"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # Keep the earliest row per pair; delete any later duplicates.
    op.execute("""
        DELETE FROM organization_memberships
        WHERE id NOT IN (
            SELECT MIN(id) FROM organization_memberships
            GROUP BY user_id, organization_id
        )
    """)
    op.execute("""
        DELETE FROM team_memberships
        WHERE id NOT IN (
            SELECT MIN(id) FROM team_memberships
            GROUP BY user_id, team_id
        )
    """)

    op.create_index(
        "ix_organization_memberships_user_org_unique",
        "organization_memberships",
        ["user_id", "organization_id"],
        unique=True,
    )
    op.create_index(
        "ix_team_memberships_user_team_unique",
        "team_memberships",
        ["user_id", "team_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_team_memberships_user_team_unique", table_name="team_memberships")
    op.drop_index("ix_organization_memberships_user_org_unique", table_name="organization_memberships")
