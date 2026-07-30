"""add licensing tables

Revision ID: a1b2c3d4e5f6
Revises: 9088038560c9
Create Date: 2026-07-28 00:00:01.000000
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic import op
import sqlalchemy as sa


if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = 'f6e5d4c3b2a1'
down_revision: str | None = 'd4c3b2a1f6e5'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "licenses",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("edition", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("license_key", sa.String(), nullable=False),
        sa.Column("issued_to", sa.String(), nullable=False, server_default=""),
        sa.Column("company", sa.String(), nullable=False, server_default=""),
        sa.Column("email", sa.String(), nullable=False, server_default=""),
        sa.Column("max_users", sa.Integer(), nullable=True),
        sa.Column("max_organizations", sa.Integer(), nullable=True),
        sa.Column("expires_at", sa.String(), nullable=False, server_default=""),
        sa.Column("features", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("signature", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_licenses_license_key"), "licenses", ["license_key"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_licenses_license_key"), table_name="licenses")
    op.drop_table("licenses")
