"""Add identity provider, SSO session, and account link tables.

Phase 26 — Enterprise Identity & Single Sign-On (SSO).

Revision ID: kkllmm001122
Revises: jjkkll001122
Create Date: 2026-07-29 06:00:00.000000
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "kkllmm001122"
down_revision: str | None = "jjkkll001122"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "identity_providers",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("protocol", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("issuer", sa.String(), nullable=False, server_default=""),
        sa.Column("domain_hint", sa.String(), nullable=False, server_default=""),
        sa.Column("role_mappings_json", sa.String(), nullable=True),
        sa.Column("group_mappings_json", sa.String(), nullable=True),
        sa.Column("jit_provisioning", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("auto_link_users", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("enforce_sso", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("metadata_xml", sa.String(), nullable=True),
        sa.Column("saml_config_json", sa.String(), nullable=True),
        sa.Column("oidc_config_json", sa.String(), nullable=True),
        sa.Column("ldap_config_json", sa.String(), nullable=True),
        sa.Column("oauth2_config_json", sa.String(), nullable=True),
        sa.Column("organization_id", sa.String(), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_identity_providers_protocol", "identity_providers", ["protocol"])
    op.create_index("ix_identity_providers_domain", "identity_providers", ["domain_hint"])

    op.create_table(
        "sso_sessions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("provider_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("external_user_id", sa.String(), nullable=False, server_default=""),
        sa.Column("idp_session_id", sa.String(), nullable=False, server_default=""),
        sa.Column("idp_assertion", sa.Text(), nullable=False, server_default=""),
        sa.Column("attributes_json", sa.String(), nullable=True),
        sa.Column("session_index", sa.String(), nullable=False, server_default=""),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False, server_default=""),
        sa.Column("last_activity", sa.String(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sso_sessions_provider", "sso_sessions", ["provider_id"])
    op.create_index("ix_sso_sessions_user", "sso_sessions", ["user_id"])

    op.create_table(
        "account_links",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("provider_id", sa.String(), nullable=False),
        sa.Column("external_user_id", sa.String(), nullable=False),
        sa.Column("external_username", sa.String(), nullable=False, server_default=""),
        sa.Column("external_email", sa.String(), nullable=False, server_default=""),
        sa.Column("linked_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("provider_id", "external_user_id"),
    )
    op.create_index("ix_account_links_user", "account_links", ["user_id"])
    op.create_index("ix_account_links_provider", "account_links", ["provider_id"])


def downgrade() -> None:
    op.drop_table("account_links")
    op.drop_table("sso_sessions")
    op.drop_table("identity_providers")
