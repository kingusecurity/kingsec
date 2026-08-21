"""rename stale indexes to match models.py

Phase 17: the tracked migration chain and the ORM metadata in models.py
have carried mismatched index names since at least 2026-08-19 (Phase 15/16
investigation) - purely index-naming/attribute drift, not a column-level
difference. Verified across three sources for all ten affected tables
(account_links, asset_history, asset_relationships, cve_entries,
dead_letter_entries, exposures, identity_providers, job_leases,
job_queue_entries, sso_sessions) before writing this migration: the
autogenerate diff contains only drop_index/create_index (zero
add_column/drop_column/alter_column), every column referenced by both the
old and new index names already exists identically in models.py and in
the live sqlite_master schema produced by `alembic upgrade head`, and the
migrations that originally created these tables used ad hoc index names
(e.g. `ix_account_links_provider` on the `provider_id` column, not a
column named `provider`) predating SQLAlchemy's current auto-naming
convention. See docs/audits/KINGSEC-PHASE-17-SCHEMA-DRIFT-MIGRATION-REPORT.md
for the full evidence.

Two of the thirty-two index changes are not pure renames and are called
out explicitly rather than left implicit in the op list below:
  * `ix_cve_entries_cve_code` changes `unique=False` -> `unique=True`,
    matching CveEntryModel.cve_code's `unique=True`; same name, same
    column, changed attribute.
  * `ix_asset_history_timestamp` and `ix_exposures_severity` are dropped
    with no replacement - models.py no longer declares `index=True` on
    AssetHistoryModel.timestamp or ExposureModel.severity. The columns
    themselves are unchanged; only the "should this be indexed" answer
    changed.
  * `ix_job_leases_job_id` is newly created (JobLeaseModel.job_id is
    `index=True, unique=True`, but the migration that created job_leases
    never indexed it - only `worker_id` was indexed at creation time).

SQLite has no `ALTER INDEX ... RENAME`, so every rename is expressed as
drop_index followed by create_index, exactly as Alembic's autogenerate
emitted it (no `batch_alter_table` needed - unlike column-level ALTER,
index drop/create run directly on SQLite). This project targets SQLite
only in practice (`database.py::build_sqlite_url` is the sole engine URL
builder; `env.py`'s `KINGSEC_STORAGE__DATABASE_URL` override exists in
comment form only, wired nowhere), so no other dialect's behavior needed
consideration.

Revision ID: 91969658a556
Revises: d1e2f3a4b5c6
Create Date: 2026-08-21 14:33:34.035013
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from alembic import op

if TYPE_CHECKING:
    pass


# revision identifiers, used by Alembic.
revision: str = "91969658a556"
down_revision: str | None = "d1e2f3a4b5c6"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.drop_index(op.f("ix_account_links_provider"), table_name="account_links")
    op.drop_index(op.f("ix_account_links_user"), table_name="account_links")
    op.create_index(op.f("ix_account_links_provider_id"), "account_links", ["provider_id"], unique=False)
    op.create_index("ix_account_links_provider_user", "account_links", ["provider_id", "external_user_id"], unique=True)
    op.create_index(op.f("ix_account_links_user_id"), "account_links", ["user_id"], unique=False)

    # No replacement - models.py no longer indexes asset_history.timestamp.
    op.drop_index(op.f("ix_asset_history_timestamp"), table_name="asset_history")

    op.drop_index(op.f("ix_asset_relationships_source"), table_name="asset_relationships")
    op.drop_index(op.f("ix_asset_relationships_target"), table_name="asset_relationships")
    op.create_index(op.f("ix_asset_relationships_source_asset_id"), "asset_relationships", ["source_asset_id"], unique=False)
    op.create_index(op.f("ix_asset_relationships_target_asset_id"), "asset_relationships", ["target_asset_id"], unique=False)

    # Same name, same column (cve_code) - only the uniqueness constraint changes.
    op.drop_index(op.f("ix_cve_entries_cve_code"), table_name="cve_entries")
    op.create_index(op.f("ix_cve_entries_cve_code"), "cve_entries", ["cve_code"], unique=True)

    op.drop_index(op.f("ix_dead_letter_job"), table_name="dead_letter_entries")
    op.create_index(op.f("ix_dead_letter_entries_original_job_id"), "dead_letter_entries", ["original_job_id"], unique=False)

    # No replacement - models.py no longer indexes exposures.severity.
    op.drop_index(op.f("ix_exposures_severity"), table_name="exposures")

    op.drop_index(op.f("ix_identity_providers_domain"), table_name="identity_providers")
    op.create_index(op.f("ix_identity_providers_domain_hint"), "identity_providers", ["domain_hint"], unique=False)

    op.drop_index(op.f("ix_job_leases_worker"), table_name="job_leases")
    # New index - job_leases.job_id was never indexed until now.
    op.create_index(op.f("ix_job_leases_job_id"), "job_leases", ["job_id"], unique=True)
    op.create_index(op.f("ix_job_leases_worker_id"), "job_leases", ["worker_id"], unique=False)

    op.drop_index(op.f("ix_job_queue_job_id"), table_name="job_queue_entries")
    op.drop_index(op.f("ix_job_queue_state"), table_name="job_queue_entries")
    op.drop_index(op.f("ix_job_queue_target"), table_name="job_queue_entries")
    op.drop_index(op.f("ix_job_queue_worker"), table_name="job_queue_entries")
    op.create_index(op.f("ix_job_queue_entries_assigned_worker_id"), "job_queue_entries", ["assigned_worker_id"], unique=False)
    op.create_index(op.f("ix_job_queue_entries_job_id"), "job_queue_entries", ["job_id"], unique=False)
    op.create_index(op.f("ix_job_queue_entries_state"), "job_queue_entries", ["state"], unique=False)
    op.create_index(op.f("ix_job_queue_entries_target"), "job_queue_entries", ["target"], unique=False)

    op.drop_index(op.f("ix_sso_sessions_provider"), table_name="sso_sessions")
    op.drop_index(op.f("ix_sso_sessions_user"), table_name="sso_sessions")
    op.create_index(op.f("ix_sso_sessions_provider_id"), "sso_sessions", ["provider_id"], unique=False)
    op.create_index(op.f("ix_sso_sessions_user_id"), "sso_sessions", ["user_id"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_sso_sessions_user_id"), table_name="sso_sessions")
    op.drop_index(op.f("ix_sso_sessions_provider_id"), table_name="sso_sessions")
    op.create_index(op.f("ix_sso_sessions_user"), "sso_sessions", ["user_id"], unique=False)
    op.create_index(op.f("ix_sso_sessions_provider"), "sso_sessions", ["provider_id"], unique=False)

    op.drop_index(op.f("ix_job_queue_entries_target"), table_name="job_queue_entries")
    op.drop_index(op.f("ix_job_queue_entries_state"), table_name="job_queue_entries")
    op.drop_index(op.f("ix_job_queue_entries_job_id"), table_name="job_queue_entries")
    op.drop_index(op.f("ix_job_queue_entries_assigned_worker_id"), table_name="job_queue_entries")
    op.create_index(op.f("ix_job_queue_worker"), "job_queue_entries", ["assigned_worker_id"], unique=False)
    op.create_index(op.f("ix_job_queue_target"), "job_queue_entries", ["target"], unique=False)
    op.create_index(op.f("ix_job_queue_state"), "job_queue_entries", ["state"], unique=False)
    op.create_index(op.f("ix_job_queue_job_id"), "job_queue_entries", ["job_id"], unique=False)

    op.drop_index(op.f("ix_job_leases_worker_id"), table_name="job_leases")
    op.drop_index(op.f("ix_job_leases_job_id"), table_name="job_leases")
    op.create_index(op.f("ix_job_leases_worker"), "job_leases", ["worker_id"], unique=False)

    op.drop_index(op.f("ix_identity_providers_domain_hint"), table_name="identity_providers")
    op.create_index(op.f("ix_identity_providers_domain"), "identity_providers", ["domain_hint"], unique=False)

    op.create_index(op.f("ix_exposures_severity"), "exposures", ["severity"], unique=False)

    op.drop_index(op.f("ix_dead_letter_entries_original_job_id"), table_name="dead_letter_entries")
    op.create_index(op.f("ix_dead_letter_job"), "dead_letter_entries", ["original_job_id"], unique=False)

    op.drop_index(op.f("ix_cve_entries_cve_code"), table_name="cve_entries")
    op.create_index(op.f("ix_cve_entries_cve_code"), "cve_entries", ["cve_code"], unique=False)

    op.drop_index(op.f("ix_asset_relationships_target_asset_id"), table_name="asset_relationships")
    op.drop_index(op.f("ix_asset_relationships_source_asset_id"), table_name="asset_relationships")
    op.create_index(op.f("ix_asset_relationships_target"), "asset_relationships", ["target_asset_id"], unique=False)
    op.create_index(op.f("ix_asset_relationships_source"), "asset_relationships", ["source_asset_id"], unique=False)

    op.create_index(op.f("ix_asset_history_timestamp"), "asset_history", ["timestamp"], unique=False)

    op.drop_index(op.f("ix_account_links_user_id"), table_name="account_links")
    op.drop_index("ix_account_links_provider_user", table_name="account_links")
    op.drop_index(op.f("ix_account_links_provider_id"), table_name="account_links")
    op.create_index(op.f("ix_account_links_user"), "account_links", ["user_id"], unique=False)
    op.create_index(op.f("ix_account_links_provider"), "account_links", ["provider_id"], unique=False)
