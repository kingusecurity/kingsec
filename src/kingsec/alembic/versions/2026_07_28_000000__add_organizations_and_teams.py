"""add organizations and teams tables

Revision ID: d4c3b2a1f6e5
Revises: 9088038560c9
Create Date: 2026-07-28 00:00:00.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = 'd4c3b2a1f6e5'
down_revision: str | None = 'a1b2c3d4e5f6'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "org_activity_events",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("event_type", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("message", sa.String(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("timestamp", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "teams",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("organization_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "team_memberships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.ForeignKeyConstraint(["team_id"], ["teams.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.add_column("assessments", sa.Column("organization_id", sa.String(), nullable=True))
    op.add_column("assessments", sa.Column("team_id", sa.String(), nullable=True))
    op.add_column("assessments", sa.Column("owner_id", sa.String(), nullable=True))
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.create_foreign_key("fk_assessments_organization_id", "organizations", ["organization_id"], ["id"])
        batch_op.create_foreign_key("fk_assessments_team_id", "teams", ["team_id"], ["id"])


def downgrade() -> None:
    with op.batch_alter_table("assessments") as batch_op:
        batch_op.drop_constraint("fk_assessments_team_id", type_="foreignkey")
        batch_op.drop_constraint("fk_assessments_organization_id", type_="foreignkey")
    op.drop_column("assessments", "owner_id")
    op.drop_column("assessments", "team_id")
    op.drop_column("assessments", "organization_id")
    op.drop_table("team_memberships")
    op.drop_table("teams")
    op.drop_table("organization_memberships")
    op.drop_table("org_activity_events")
    op.drop_table("organizations")
