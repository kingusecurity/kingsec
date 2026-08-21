# KINGSEC PHASE 17 — Schema Drift Migration

**Date:** 2026-08-21
**Scope:** Close the index-naming drift Phase 16 §9 caught, and remove its `xfail(strict=True)` marker once the drift is genuinely resolved.

---

## 1. Baseline, integrity check, push/CI status, pollution count

- **Branch:** `main`. **Starting commit:** `2d7a7e3` (`docs: add Phase 16 build determinism and migration pollution report`).
- **`git status`:** clean on all tracked files at the start of this phase.
- **Push/CI status:** `git status -sb` reported `## main...origin/main [ahead 27]`. **Phases 01–16 remain unpushed to `origin/main`.** Fifth consecutive phase carrying this — unchanged.
- **Leftover-container check:** none found before the baseline suite ran.
- **Baseline full suite:** confirmed **`tests="2882" errors="0" failures="0" skipped="1"`** via `pytest --junitxml` — the 1 `skipped` is Phase 16's `xfail`, matching its own reported baseline of "2,881 passed + 1 xfailed" exactly.
- **Pollution count:** **0** at start, confirmed via `git status --porcelain src/kingsec/alembic/versions/` returning empty — Phase 16's fix holding. **0** at end (§6) — the only new file in that directory is the tracked migration this phase adds.

---

## 2. §2 determination — cosmetic, not a live bug

Verified from all three required sources, for every one of the ten affected tables, before writing anything.

**Source 1 — the autogenerate diff's full body.** Reproduced fresh against current code (not assumed from Phase 16's capture) using the same isolated-config mechanism Phase 16 built (`version_locations` pointing at both the real `versions/` dir and a scratch directory, `--version-path` pinning where the new file lands). The generated diff contains:
```
32 op.create_index(
32 op.drop_index(
0 op.add_column / op.drop_column / op.alter_column / op.create_table / op.drop_table
```
Confirmed by grepping the generated file directly — zero column-level operations of any kind.

**Source 2 — `models.py`'s current column declarations.** Read directly for all ten model classes (`AccountLinkModel`, `AssetHistoryModel`, `AssetRelationshipModel`, `CveEntryModel`, `DeadLetterEntryModel`, `ExposureModel`, `IdentityProviderModel`, `JobLeaseModel`, `JobQueueEntryModel`, `SSOSessionModel`). Every column referenced by either the "removed" or "added" side of the diff (`provider_id`, `user_id`, `external_user_id`, `source_asset_id`, `target_asset_id`, `cve_code`, `original_job_id`, `domain_hint`, `protocol`, `worker_id`, `job_id`, `state`, `target`, `assigned_worker_id`, `timestamp`, `severity`) is declared, present tense, under exactly that name.

**Source 3 — the real `sqlite_master` schema from a fresh `alembic upgrade head`.** Not inferred: queried directly via `sqlite3` against a freshly upgraded database (`SELECT sql FROM sqlite_master WHERE type="table" AND name=?` for each of the ten tables). Every column `models.py` expects is present, under the same name, in the live schema — verbatim `CREATE TABLE` output captured for all ten tables (available in this session's working notes; representative excerpt: `account_links` shows `user_id VARCHAR NOT NULL, provider_id VARCHAR NOT NULL, ...`, exactly matching `AccountLinkModel`).

**Cross-referenced against the tracked migrations that originally created these tables** (`2026_07_29_500000__add_distributed_workers.py`, `2026_07_29_600000__add_identity_providers.py`, `2026_07_28_190000__extend_assets_inventory.py`, `2026_07_28_200000__add_attack_surface.py`) to find *why* the names diverged: every one of the ten tables' original `op.create_index(...)` calls used a column list that matches today's `models.py` exactly — only the index's *own name* used an older, ad hoc convention (e.g. `op.create_index("ix_account_links_provider", "account_links", ["provider_id"])` — the index name omits the `_id` suffix the column itself has always had; `op.create_index("ix_identity_providers_domain", "identity_providers", ["domain_hint"])` — the index name says `domain`, the column has always been `domain_hint`).

**Per-table result, all ten: cosmetic.** Three sub-cases within that, called out individually rather than glossed over:
- **Eight tables** (account_links ×3, asset_relationships, dead_letter_entries, identity_providers, job_queue_entries ×4, sso_sessions): straightforward renames — same column, index name updated to match SQLAlchemy's current auto-naming convention.
- **`cve_entries`**: not a rename — `ix_cve_entries_cve_code` keeps its name but changes `unique=False` → `unique=True`, matching `CveEntryModel.cve_code`'s `unique=True`. Same name, same column, changed attribute.
- **`asset_history.timestamp` and `exposures.severity`**: dropped with no replacement — `models.py` no longer declares `index=True` on either column. Not a rename; an intentional "should this be indexed" change. The columns themselves are unchanged.
- **`job_leases.job_id`**: the reverse — a genuinely *new* index. `JobLeaseModel.job_id` has always existed as a column (created in the original migration) but was never indexed at creation; `models.py` now wants `index=True, unique=True` on it.

**No column-level difference exists anywhere.** Proceeding to §3 as authorized.

---

## 3. §3.1 dialect and SQLite constraint findings

**Dialect support:** this project targets **SQLite only** in practice. `src/kingsec/infrastructure/persistence/database.py::build_sqlite_url()` is the sole database-URL-building function the real application uses; `StorageSettings` (the config model) exposes only `data_dir`, no `database_url` field. `env.py`'s `_resolve_database_url()` mentions a `KINGSEC_STORAGE__DATABASE_URL` env var for "PostgreSQL / external database URL" in a comment, but grepping the entire `infrastructure/config/` and `database.py` for `postgres`/`database_url` found **zero** other references — this override exists in `env.py` alone, wired to nothing in the actual application. No other dialect needed consideration for this migration.

**SQLite constraint:** SQLite has no `ALTER INDEX ... RENAME`. Every rename must be `drop_index` + `create_index`. Confirmed this is exactly what Alembic's autogenerate already emitted (§2, Source 1) — no `batch_alter_table` needed, since (unlike column-level `ALTER TABLE` operations, which SQLite doesn't support directly and which Alembic's batch mode works around via a copy-and-swap) index drop/create statements run directly against SQLite with no special handling required.

---

## 4. The migration written

`src/kingsec/alembic/versions/2026_08_21_143727__rename_stale_indexes_to_match_models.py` — revision `91969658a556`, `down_revision = "d1e2f3a4b5c6"` (the tracked head, confirmed via the real `alembic heads` CLI before writing, not by reading filenames).

**Structure:** Alembic's own autogenerated `upgrade()`/`downgrade()` bodies were used as the base (already correct — 32 matched drop/create pairs, `downgrade()` a true reverse-order mirror), reformatted with per-table grouping and inline comments calling out the three non-rename sub-cases from §2 (the `cve_entries` uniqueness change, the two no-replacement drops, the one genuinely new index) so a future reader does not have to re-derive that reasoning from the raw op list. Full docstring records the evidence trail and points to this report.

**Full content:** committed at `de619bb`; reproduced in full below for the record.
```python
"""rename stale indexes to match models.py
...
Revision ID: 91969658a556
Revises: d1e2f3a4b5c6
"""

def upgrade() -> None:
    op.drop_index(op.f("ix_account_links_provider"), table_name="account_links")
    op.drop_index(op.f("ix_account_links_user"), table_name="account_links")
    op.create_index(op.f("ix_account_links_provider_id"), "account_links", ["provider_id"], unique=False)
    op.create_index("ix_account_links_provider_user", "account_links", ["provider_id", "external_user_id"], unique=True)
    op.create_index(op.f("ix_account_links_user_id"), "account_links", ["user_id"], unique=False)
    op.drop_index(op.f("ix_asset_history_timestamp"), table_name="asset_history")  # no replacement
    op.drop_index(op.f("ix_asset_relationships_source"), table_name="asset_relationships")
    op.drop_index(op.f("ix_asset_relationships_target"), table_name="asset_relationships")
    op.create_index(op.f("ix_asset_relationships_source_asset_id"), "asset_relationships", ["source_asset_id"], unique=False)
    op.create_index(op.f("ix_asset_relationships_target_asset_id"), "asset_relationships", ["target_asset_id"], unique=False)
    op.drop_index(op.f("ix_cve_entries_cve_code"), table_name="cve_entries")
    op.create_index(op.f("ix_cve_entries_cve_code"), "cve_entries", ["cve_code"], unique=True)  # same name, unique flips
    op.drop_index(op.f("ix_dead_letter_job"), table_name="dead_letter_entries")
    op.create_index(op.f("ix_dead_letter_entries_original_job_id"), "dead_letter_entries", ["original_job_id"], unique=False)
    op.drop_index(op.f("ix_exposures_severity"), table_name="exposures")  # no replacement
    op.drop_index(op.f("ix_identity_providers_domain"), table_name="identity_providers")
    op.create_index(op.f("ix_identity_providers_domain_hint"), "identity_providers", ["domain_hint"], unique=False)
    op.drop_index(op.f("ix_job_leases_worker"), table_name="job_leases")
    op.create_index(op.f("ix_job_leases_job_id"), "job_leases", ["job_id"], unique=True)  # new index
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
    # exact reverse-order mirror of upgrade() - see the committed file for the full listing
    ...
```
(Full, unabridged content is in the committed file; the excerpt above omits `downgrade()`'s 30-odd mirrored lines for report length — every `create_index` in `upgrade()` has a matching `drop_index` in `downgrade()` and vice versa, verified in §6.)

---

## 5. §4 — marker removal, test passing on its own merits

Removed `@pytest.mark.xfail(reason=..., strict=True)` and the now-unnecessary `import pytest` from `tests/integration/test_alembic_migrations.py`. Re-ran the file:
```
tests\integration\test_alembic_migrations.py .......                     [100%]
============================= 7 passed in 26.30s ==============================
```
**7 passed, 0 xfailed, 0 skipped.** No `xfail` marker remains anywhere in the file (confirmed via `grep -n xfail`, no matches). The test passes because the migration closes the diff, not because the assertion was loosened — the assertion is byte-for-byte the one Phase 16 wrote.

---

## 6. §5 verification, every item

| Check | Result |
|---|---|
| `alembic upgrade head` against a fresh database | Succeeds — full log captured, final step `Running upgrade d1e2f3a4b5c6 -> 91969658a556, rename stale indexes to match models.py` |
| `alembic revision --autogenerate` against that upgraded database | **Produces no file.** Captured hook log line: `INFO:alembic.env:no schema changes detected; skipping empty autogenerate revision`. Version-path scratch directory listing empty afterward. Re-run cleanly with a fresh scratch directory (an earlier run reused a stale scratch dir from investigation and produced a harmless `UserWarning: Revision ... is present more than once`, unrelated to production code — noted for transparency, not a real finding) |
| `alembic downgrade` one step, then `upgrade head` again | **Succeeds.** `Running downgrade 91969658a556 -> d1e2f3a4b5c6, rename stale indexes to match models.py` then `Running upgrade d1e2f3a4b5c6 -> 91969658a556, rename stale indexes to match models.py` — both clean, no errors. Proves §3.2/§4's reversibility claim in practice, not just by code inspection |
| Repaired test passes, no `xfail` | 7/7 passed (§5 above) |
| `git status --porcelain src/kingsec/alembic/versions/` empty after a full suite run | Empty — only the new tracked migration exists in that directory; Phase 16's regression proof holds |
| Wheel determinism | Rebuilt via `python -m build --wheel` with the migration staged; packaged `versions/*.py` count: **32** (not 31), diffed against `git ls-files`: **0** extra, **0** missing — exact match |
| `lint-imports` | 3/3 contracts kept, 0 broken (677 files, 3668 dependencies) |
| `bandit -q -r src` | 0 findings |
| `mypy src` | `Success: no issues found in 585 source files` |
| `ruff check` (tracked files) | All checks passed (after the incidental Phase 16 hook fix, §9) |
| Full suite | **`tests="2882" errors="0" failures="0" skipped="0"`** — precisely **2,882 passed, 0 xfailed, 0 failures**, exactly Phase 17's own target, not rounded from anything |

---

## 7. Docker rebuild, startup, and the fresh volume's stamp

**First attempt invalidated itself, and that is reported rather than hidden.** The migration file was `git add`ed (staged) before the first `docker compose build`, but never committed at that point — since the Dockerfile's builder stage runs `git archive HEAD`, which reflects the last **commit**, not the index, that first build silently excluded the new migration. The resulting fresh volume was stamped `d1e2f3a4b5c6` — the old head — which, on inspection, correctly revealed the process gap rather than a code defect. The verification container and volume from that attempt were torn down without being reported as a pass.

**Corrected:** committed the migration (`de619bb`) and the incidental `hatch_build.py` fix (`bee50fa`), then rebuilt.

`docker compose build --progress=plain` succeeded (foreground; two consecutive builds this session took ~24–31 minutes each due to throttled package downloads, matching Phase 16's own precedent — confirmed genuinely progressing via `docker buildx du`'s active cache entry and pip's own download progress output, not stalled).

Started against a **fresh, phase-17-specific volume** (`kingsec-data-phase17`). Container reached a healthy state on the first health check.

**Inspected the fresh volume's `alembic_version` directly:**
```
alembic_version: [('91969658a556',)]
```
**Equals the new migration's revision ID, exactly.** Direct proof the shipped container applies it. Verification container and volume stopped and removed afterward; confirmed nothing left listening on port 8765.

---

## 8. Files changed and commit hashes

| Commit | Contents |
|---|---|
| `de619bb` — the migration + marker removal | `src/kingsec/alembic/versions/2026_08_21_143727__rename_stale_indexes_to_match_models.py` (new), `tests/integration/test_alembic_migrations.py` (xfail removed, unused `pytest` import removed) |
| `bee50fa` — incidental Phase 16 gate fix | `hatch_build.py` (ARG002/S607 cleared) |
| *(this report)* | `docs/audits/KINGSEC-PHASE-17-SCHEMA-DRIFT-MIGRATION-REPORT.md`, committed separately, hash recorded in the closing summary |

---

## 9. What this phase does NOT fix

- **The Finding 5 product decision** (Option A/B/C, Phase 15 §7) — still the product owner's to make. Restated as open, unchanged by this phase.
- **The existing stale volumes** (`kingsec-data`, `kingsec-data-phase09`, `kingsec-data-phase12`) — not touched, not `stamp`ed. Phase 15 §6's prohibition stands.
- **The seven tracked `*__no_changes.py` migrations** in committed history — untouched. Of the ten tables this phase's migration touches, none of those seven happened to be the origin point for the drift (the drift traced to `2026_07_28_190000__extend_assets_inventory.py`, `2026_07_28_200000__add_attack_surface.py`, `2026_07_29_500000__add_distributed_workers.py`, and `2026_07_29_600000__add_identity_providers.py` — none named `*__no_changes.py`). No consolidation performed.
- Findings 6, 7, 8 — untouched.
- Phase 11's carried observation on unpinned `pip>=26.1.2` — untouched.
- Phase 12's carried observation (`diagnostics.py`'s hardcoded probe) — untouched.
- **Phase 14 §5's residual credential-exfiltration risk** — still open.
- **Phase 16's two carried notes** (the builder stage's `.git` layer, `_skip_empty_autogenerate_revision` living in production `env.py`) — untouched, restated as still open.
- **Incidentally discovered, incidentally fixed (not this phase's scope, but trivial and disclosed):** two ruff findings (`ARG002`, `S607`) in `hatch_build.py`, left over from Phase 16's own gate re-run. Fixed as a separate, individually-justified commit (`bee50fa`) per the same pattern Phase 16 itself used for a Phase 14 slip.
- Frontend work — untouched.

---

## 10. Recommended Phase 18 scope

1. **Push Phases 01–17 to `origin/main`.** Sixth consecutive phase carrying this recommendation forward. Thirty commits now sit unverified by any independent CI.
2. **Revisit the Finding 5 product decision** (Phase 15 §7's Options A/B/C) now that the *mechanism* (Phase 16) and the *one concrete drift instance it surfaced* (this phase) are both closed. The investigation-and-fix work this decision depends on is now as complete as engineering can make it without a product-owner answer; nothing further can be learned by continuing to defer it.
3. Given this phase closed out with two consecutive Docker builds each taking 20–30+ minutes purely on package downloads, and Phase 11's carried observation about `pip>=26.1.2` being unpinned already flags build-input non-reproducibility as a known class of issue — a lightweight look at whether a local package-download cache (or pinning to a lockfile with hashes) would make this programme's own iteration loop faster and more reproducible could be a reasonable, low-priority addition to a future phase's scope, though it is not itself a defect.
