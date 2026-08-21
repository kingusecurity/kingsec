# KINGSEC PHASE 18 — Migration Data Safety

**Date:** 2026-08-21
**Scope:** Determine whether Phase 17's migration (`91969658a556`, three new/changed `unique=True` indexes) can fail against populated data, since every Phase 17 verification ran against an empty database.

---

## 1. Baseline, integrity check, push/CI status, pollution count

- **Branch:** `main`. **Starting commit:** `0e8a601` (`docs: add Phase 17 schema drift migration report`).
- **`git status`:** clean on all tracked files at the start of this phase.

### Push/CI status — a major change from the prior six phases

`git status -sb` reported `## main...origin/main` with **no "ahead N" marker** — `git rev-list --count origin/main..HEAD` returned **0**. **Local `main` and `origin/main` are now identical.** The repository was pushed at some point after Phase 17's report was written — not by this session (no `git push` was ever issued in Phases 09–17's work). This is the first time in six consecutive phases this has changed.

**This triggered the programme's first-ever independent CI run — and it failed.** `gh run list` showed the push's CI run (`32472997920`, 2026-08-21T10:31:06Z) as `completed failure`. Investigated immediately via `gh run view --log-failed`: the `Lint (Ruff)` step failed identically across all three Python-version matrix jobs (3.11/3.12/3.13), on `F401 'alembic.runtime.revision.MigratorCollection' imported but unused` in Phase 17's migration file (`src/kingsec/alembic/versions/2026_08_21_143727__rename_stale_indexes_to_match_models.py:55`). Everything downstream of `Lint (Ruff)` (mypy, import-linter, bandit, pip-audit, pytest) never ran, since the job stops at the first failed step. Frontend Quality Gates passed independently.

**Root cause, confirmed precisely:** this project's own gate-checking convention throughout Phases 13–17 used `git ls-files '*.py' | xargs ruff check` (tracked-files-only) instead of CI's actual `ruff check .` (full repo). `git ls-files` only lists files tracked/staged *at the moment it runs*. Phase 17's migration file was written, gate-checked with this scoped command *before* being `git add`ed, then staged and committed afterward with no re-check — so the file was invisible to every local ruff run that phase performed, and a real, genuine unused-import error shipped to `main` undetected. Reproduced directly: `ruff check src/kingsec/alembic/versions/2026_08_21_143727__rename_stale_indexes_to_match_models.py` fails identically to CI, confirming this was never a CI-environment quirk.

**Fixed immediately, as the first action of this phase** (commit `a9e65e6`), before any of Phase 18's own investigation work: removed the unused import (this repo's older tracked migrations use `if TYPE_CHECKING: pass`; Phase 17's file used a newer Alembic template version's boilerplate that imports `MigratorCollection` for a type hint the migration never needs). Verified against CI's *exact* invocation, `ruff check .` from the repo root: reproduces the failure before the fix, clean after. This project's own `kingsec-gate-ruff-scope` memory note already said to use `ruff check .`, not the tracked-files variant — updated that note with this concrete confirmation, since the reason for the earlier deviation (Phase 15's alembic pollution contaminating full-repo scans) no longer applies now that Phase 16 eliminated the pollution.

- **Leftover-container check:** none found before the baseline suite ran.
- **Baseline full suite** (run before the ruff fix, since it doesn't affect test collection): confirmed **`tests="2882" errors="0" failures="0" skipped="0"`** — Phase 17's baseline exactly.
- **Pollution count:** **0** at start (confirmed via `git status --porcelain src/kingsec/alembic/versions/`), **0** at end (§7).
- **Noted the `git archive HEAD` gotcha** Phase 17 hit: all Docker verification in this phase happens only after every relevant change is committed, not merely staged.

## 2. §2.1 per-index duplicate reachability — insert/update paths cited

All three writes follow the same shape: an application-layer "check existence via a natural-key lookup, then construct-and-insert if not found" pattern, with **no database-level enforcement relied upon by the application code** (the ORM `unique=True` markers being added by Phase 17 are the first explicit enforcement at that layer) and **no atomic upsert** — each is check-then-act across separate operations.

- **`job_leases.job_id`** — `JobLeaseManager.acquire()` (`src/kingsec/application/distributed/job_dispatcher.py:25-46`): calls `self._lease_repo.find_by_job(job_id)` (line 31); if an active lease exists, raises `DuplicateJobAssignmentError` (line 33); if an expired one exists, deletes it (line 35) *then* creates a new one via `self._lease_repo.create(lease)` (line 46, `src/kingsec/infrastructure/persistence/repositories/lease.py:21-26`, a plain `session.add()`). This is a genuine multi-step, non-atomic sequence — a classic TOCTOU race if invoked concurrently for the same `job_id`. **However**, `JobLeaseManager`/`JobDispatcher` are registered in the DI container (`bootstrap/composition.py:1641-1654`) but have **zero callers anywhere else in the codebase** — no route, no scheduler, no background task resolves or invokes them (confirmed by `grep -rn "JobDispatcher\b" src/` outside its own definition and DI registration: no matches). The distributed job-dispatch subsystem is fully built but not yet wired to any entry point.
- **`cve_entries.cve_code`** — `SQLAlchemyCveRepository.save()` (`src/kingsec/infrastructure/persistence/repositories/threat_intelligence.py:35-45`) de-duplicates via `session.get(CveEntryModel, str(entry.id))` — **keyed on primary key `id`, not `cve_code`**. `CveId.generate()` (`src/kingsec/domain/identifiers.py:199-201`) produces a fresh random UUID every call, with no deterministic relationship to `cve_code`. The enrichment path `_build_entry()` (`src/kingsec/application/threat_intelligence/enrichment.py:91-100`) always calls `CveId.generate()` unconditionally. Two call sites use this: `ThreatIntelligenceService.get_cve_by_code()` (`service.py:76-88`) checks `find_by_cve_code()` first and returns early on a hit — safe. `sync_cve()` (`service.py:90-121`) enriches *first* (generating a fresh id regardless), then checks `find_by_cve_code()` (line 95) and, if found, re-keys the result onto `existing.id` (line 98) before saving — also safe *sequentially*, but has the same TOCTOU race as `job_leases` under concurrent calls to `sync_cve()` for the same `cve_code`.
- **`account_links (provider_id, external_user_id)`** — `JITProvisioningService.provision()` (`src/kingsec/application/idp/jit_provisioning.py:25-83`): calls `find_by_provider_and_external_id()` (line 34) first; returns early if found (lines 35-38); only constructs a fresh `AccountLink(id=str(uuid4()), ...)` and calls `save()` (which `session.merge()`s by primary key, `identity.py:142-147`) when not found. Same check-then-act shape, same TOCTOU race under concurrent SSO logins for the same external identity.

**Observation, not a Phase 18 finding requiring action:** all three application-layer dedup checks are, by themselves, races waiting to happen under concurrency. §2.2 shows why this has not mattered in practice.

## 3. §2.2 reproduction — verbatim, per index, including the atomicity finding

**Method:** for each index, built a fresh SQLite database, ran `alembic upgrade d1e2f3a4b5c6` (the pre-migration head, confirmed via `alembic heads` before Phase 17 committed its migration), then attempted to insert a legitimate row followed by a duplicate via direct SQL (simulating what the §2.1 races would produce), each individually committed (matching how the real repositories commit per operation).

**`job_leases.job_id`:**
```
INSERT INTO job_leases (...) VALUES ('lease-A', 'job-DUP', ...)  -- committed, succeeds
INSERT INTO job_leases (...) VALUES ('lease-B', 'job-DUP', ...)  -- attempted
sqlite3.IntegrityError: UNIQUE constraint failed: job_leases.job_id
```
**`cve_entries.cve_code`:**
```
sqlite3.IntegrityError: UNIQUE constraint failed: cve_entries.cve_code
```
**`account_links (provider_id, external_user_id)`:**
```
sqlite3.IntegrityError: UNIQUE constraint failed: account_links.provider_id, account_links.external_user_id
```

**All three duplicates were rejected at insert time, at revision `d1e2f3a4b5c6` — before Phase 17's migration ever runs.** Investigated why: each table's *original* creation migration already declares a table-level `sa.UniqueConstraint` — missed in Phase 17's own investigation, which read these files via partial `grep` excerpts that didn't include the constraint lines:
- `job_leases`: `sa.UniqueConstraint("job_id")` — `2026_07_29_500000__add_distributed_workers.py:75`
- `cve_entries`: `sa.UniqueConstraint("cve_code")` — `2026_07_29_100000__add_threat_intelligence.py:47`
- `account_links`: `sa.UniqueConstraint("provider_id", "external_user_id")` — `2026_07_29_600000__add_identity_providers.py:80`

**All three columns have been protected at the database level since each table's original creation (2026-07-28/29) — predating `91969658a556` entirely.** Phase 17's migration does not newly *enforce* anything for these three; it adds a named, explicit index that mirrors a constraint SQLite has already been implicitly indexing and enforcing the whole time. **No reachable migration failure exists for any of the three indexes**, demonstrated by trying to insert duplicates through direct SQL against the real schema and being rejected, not by reading the code and assuming it looks fine.

Confirmed the corollary directly: `alembic upgrade head` against each of these single-legitimate-row databases succeeded cleanly (verbatim: `Running upgrade d1e2f3a4b5c6 -> 91969658a556, rename stale indexes to match models.py`, no errors), and a downgrade→upgrade round trip on the `job_leases` database preserved the row (`[('lease-A', 'job-DUP')]` present after `downgrade -1` then `upgrade head`).

### Atomicity — a separate, real finding

Independent of the (unreachable) duplicate-value question, tested atomicity directly by forcing a **different** kind of mid-migration failure: pre-created `ix_sso_sessions_provider_id` (one of the last indexes `upgrade()` creates, operation ~30 of 32) by hand before running the migration, so the migration's own attempt to create the same name collides.

**Result:**
```
alembic_version: [('d1e2f3a4b5c6',)]   -- the OLD, pre-migration revision
```
but `account_links` (the *first* table `upgrade()` touches) already showed the **new** index names (`ix_account_links_provider_id`, `ix_account_links_provider_user`, `ix_account_links_user_id`), and `sso_sessions` had already lost its *old* index names (`ix_sso_sessions_provider`/`ix_sso_sessions_user`) before the forced failure. **Roughly 29 of the migration's 32 operations executed and persisted to disk, while `alembic_version` was never updated to reflect any of it** — despite `env.py`'s `run_migrations_online()` wrapping the whole run in `context.begin_transaction()`. This is precisely the "far worse than failing cleanly" state the phase's own principle describes: the database's actual index set matches neither the old revision nor the new one, and no revision in the chain describes it.

**This is a real, demonstrated defect — but it is not specific to `91969658a556` or to the uniqueness question this phase was scoped around.** It is a general property of how this project's SQLite migrations execute `drop_index`/`create_index` sequences (observed here; the underlying mechanism is most likely SQLite's own DDL-autocommit behavior interacting with SQLAlchemy's transaction wrapping, though the exact driver-level cause was not further isolated — labeled UNKNOWN). Fixing general DDL atomicity (e.g., explicit `BEGIN`/`COMMIT` wrapping tuned for SQLite, or per-statement `batch_alter_table` even for index-only operations) is a cross-cutting change to the migration *tooling*, not to this one migration, and is reported here rather than fixed — see §5 for why, and §12 for the Phase 19 recommendation.

## 4. §2.3 the two index removals — git provenance and query-usage findings

**`asset_history.timestamp`:** `git log -S "class AssetHistoryModel"` traces `AssetHistoryModel`'s introduction to commit `21650f0` ("feat: Phase 18 - Asset Inventory & Continuous Asset Management" — the *product's* own internal feature-phase numbering, unrelated to this audit programme's phase numbers). At that commit, `timestamp: Mapped[str] = mapped_column(String, nullable=False)` **never** had `index=True` — while the *same commit* also introduced the migration `2026_07_28_190000__extend_assets_inventory.py`, which explicitly creates `ix_asset_history_timestamp`. **Same-commit, day-one inconsistency between the model and its own migration, not a later removal.**

**`exposures.severity`:** same pattern. `git show 7c0af639b0...` (introducing `ExposureModel`, "feat: Phase 19 - Attack Surface Management") shows `severity: Mapped[str] = mapped_column(String, nullable=False, default="medium")` — never `index=True` — while the same-day migration `2026_07_28_200000__add_attack_surface.py` explicitly creates `ix_exposures_severity`.

**Checked whether a later commit explains it instead:** found and read commit `22eceb1` ("fix: repair broken API routing, DI wiring, and migration bugs across the platform," 2026-07-31, itself Claude-Sonnet-5-co-authored) — its message explicitly says *"alembic: remove duplicate `index=True` + `create_index()` pairs on `asset_tags`, `asset_technologies`, `asset_relationships`, and `asset_history`, which made `alembic upgrade head` fail on every fresh install."* Read the actual diff: this commit removed `index=True` from **inline `sa.Column(..., index=True)` declarations inside `op.create_table()` calls** for `asset_tags.asset_id`, `asset_technologies.asset_id`, `asset_relationships.source_asset_id`/`target_asset_id`, and `asset_history.asset_id` — columns that had **both** an implicit index (from `Column(index=True)`) **and** a separate explicit `op.create_index(...)` for the same target, genuinely colliding on a fresh install. **This commit never touched `timestamp` or `severity` at all** — neither had the inline `index=True` bug to begin with (confirmed: the diff's before/after both show `sa.Column("timestamp", ...)` with no `index=True`, at any point). This rules out the one plausible "later, deliberate removal" candidate in this repository's history.

**Query usage — both columns are live, not vestigial:**
- `ExposureModel.severity`: used in a `WHERE` filter (`src/kingsec/infrastructure/persistence/repositories/attack_surface.py:310`, `q.where(ExposureModel.severity == filter_.severity.value)`) and `GROUP BY` (`attack_surface.py:76`).
- `AssetHistoryModel.timestamp`: used in `ORDER BY` (`src/kingsec/infrastructure/persistence/repositories/asset_inventory.py:244`, `.order_by(AssetHistoryModel.timestamp.desc())`).

**Finding: the removal looks accidental, not deliberate.** Both columns' missing `index=True` traces to the same day the model and its migration were both first authored — not to any later, intentional change — and both columns are actively filtered/ordered on in exactly the query shapes an index would help. This is reported as a recommendation for the product owner; **no index was added back**, per §5 of this phase's prompt.

## 5. §3 approach — not triggered; amend-vs-follow-up moot

Per this phase's own framing, §3's implementation menu ("Implementation — Only If §2.2 Demonstrates A Real Failure") applies specifically to the uniqueness-conflict scenario. §2.2 demonstrated **no such failure is reachable** for any of the three indexes. None of the four listed options (pre-flight check, data remediation, dropping `unique=True`, documenting as an accepted constraint) apply — there is nothing to pre-flight-check, remediate, or accept, since the constraint has been safely enforced since 2026-07-28/29 regardless of what `91969658a556` does. **No migration change was made.** The amend-vs-follow-up question is therefore moot for this concern.

The one genuine defect this phase found — general DDL non-atomicity (§3) — is deliberately **not** remediated here either, for a reason distinct from "§2.2 found nothing": fixing it is a cross-cutting change to how *every* future SQLite migration executes, not a targeted fix to `91969658a556` specifically, and is disproportionate to include unilaterally in a phase scoped around one migration's data-safety question. Recommended for Phase 19 (§12).

## 6. Fix implemented — none to this migration; one incidental gate fix

No changes to `91969658a556` or any migration file. The only source change this phase made is the incidental CI-fix (§1, commit `a9e65e6`) — a one-line diff removing an unused `TYPE_CHECKING` import, unrelated to the uniqueness/atomicity investigation itself.

## 7. §4 verification, every item, populated and empty

| Check | Result |
|---|---|
| Populated-database upgrade succeeds | Yes, for all three indexes individually and combined — verbatim in §3 |
| Duplicate-insert rejection, if forced | `sqlite3.IntegrityError: UNIQUE constraint failed: <table>.<column(s)>` — specific, attributable, per §3 |
| Atomicity | **Not atomic** — confirmed via forced mid-migration failure, §3. `alembic_version` stayed at `d1e2f3a4b5c6` while ~29/32 operations persisted |
| Fresh-database `upgrade head` | Still succeeds — Phase 17's path unregressed, confirmed via the new regression test and the full suite |
| Downgrade → upgrade round trip, empty database | Succeeds (Phase 17's own coverage, re-confirmed via the full suite) |
| Downgrade → upgrade round trip, **populated** database | Succeeds — `job_leases` row `('lease-A', 'job-DUP')` survived `downgrade -1` → `upgrade head` intact |
| `alembic revision --autogenerate` produces no file | Still true (Phase 16/17's hook and isolation mechanism untouched by this phase; covered by the full suite's `TestMigrationAutogenerate`, still passing) |
| `git status --porcelain src/kingsec/alembic/versions/` empty after a full suite run | Empty — confirmed |
| Wheel determinism | Rebuilt: **32** `versions/*.py` files packaged, diffed against `git ls-files`: **0** extra, **0** missing |
| `lint-imports` | 3/3 contracts kept, 0 broken (677 files, 3668 dependencies) |
| `bandit -q -r src` | 0 findings |
| `mypy src` | `Success: no issues found in 585 source files` |
| `ruff check .` (the real, CI-matching invocation — not the tracked-files variant, per §1) | All checks passed |
| Full suite | **`tests="2884" errors="0" failures="0" skipped="0"`** — Phase 17's 2,882 baseline plus the 2 new regression tests below, precisely |

## 8. Regression test added

`tests/integration/test_alembic_migrations.py::TestMigrationWithPopulatedUniqueConstrainedData` (commit `e467a5f`), two tests:
- `test_upgrade_succeeds_against_populated_tables` — builds a database at `d1e2f3a4b5c6`, inserts one legitimate row into each of the three tables, runs `upgrade head`, asserts success, asserts the new indexes exist, and asserts all three rows survived untouched.
- `test_upgrade_fails_cleanly_if_duplicates_somehow_exist` — proves that if a duplicate ever did reach this point, SQLite raises the specific `IntegrityError` naming `job_leases.job_id`, not a generic failure.

This is the regression guard §4 requires: it does not merely re-prove today's finding once, it protects against a *future* change silently weakening or removing one of the underlying `UniqueConstraint`s — the actual thing standing between "safe" and "this migration can fail on real data" — going undetected, exactly the class of gap Phase 16 demonstrated when an assertion that could never fail sat in the suite for the whole programme.

## 9. Docker rebuild, startup, and the fresh volume's stamp

`docker compose build --progress=plain` succeeded from a fully committed tree (commits `a9e65e6`, `e467a5f` — the `git archive HEAD` gotcha noted in §6 explicitly avoided this time). Started against a fresh, phase-18-specific volume. Container reached a healthy state on the first check.

Inspected the fresh volume's `alembic_version` directly:
```
alembic_version: [('91969658a556',)]
```
**Confirmed: unchanged from Phase 17, exactly as expected**, since this phase made no migration changes — the shipped container still applies the same, unmodified migration cleanly. Verification container and volume stopped and removed afterward; confirmed nothing left listening on port 8765.

## 10. Files changed and commit hashes

| Commit | Contents |
|---|---|
| `a9e65e6` — incidental CI fix | `src/kingsec/alembic/versions/2026_08_21_143727__rename_stale_indexes_to_match_models.py` (unused import removed) |
| `e467a5f` — regression tests | `tests/integration/test_alembic_migrations.py` (+2 tests) |
| *(this report)* | `docs/audits/KINGSEC-PHASE-18-MIGRATION-DATA-SAFETY-REPORT.md` |

## 11. What this phase does NOT fix

- **The Finding 5 product decision** (Option A/B/C, Phase 15 §7) — still the product owner's to make. Restated as open.
- **The existing stale volumes** (`kingsec-data`, `kingsec-data-phase09`, `kingsec-data-phase12`) — not touched, not `stamp`ed.
- **§2.3's two index removals** — reported as looking accidental, not re-added. Recommendation for the product owner, per this phase's explicit instruction.
- **The general SQLite/Alembic DDL non-atomicity finding (§3)** — real, demonstrated, and not specific to `91969658a556`. Reported, not fixed — see §12.
- Findings 6, 7, 8 — untouched.
- Phase 11's carried observation on unpinned `pip>=26.1.2` — untouched.
- Phase 12's carried observation (`diagnostics.py`'s hardcoded probe) — untouched.
- **Phase 14 §5's residual credential-exfiltration risk** — still open.
- Phase 16's two carried notes (the builder stage's `.git` layer; `_skip_empty_autogenerate_revision` in production `env.py`) — untouched.
- Phase 17 §10's build-caching suggestion — untouched, a convenience item.
- Frontend work — untouched.

## 12. Recommended Phase 19 scope

1. **Investigate and fix the general SQLite/Alembic DDL non-atomicity finding (§3).** This is now the most concrete, well-evidenced open defect in the migration system: a mid-migration failure — for any reason, not just the uniqueness question this phase closed out — can leave the database with a partially-applied schema and a stale `alembic_version` stamp, a state no revision describes. Candidates to evaluate: explicit transaction control tuned for SQLite's DDL-autocommit behavior, or `batch_alter_table` even for pure index operations. This is squarely a "determine before fixing" phase in its own right — the exact mechanism (SQLite driver-level vs. SQLAlchemy-level) is currently labeled UNKNOWN and should be pinned down first.
2. **Present §2.3's finding to the product owner**: `asset_history.timestamp` and `exposures.severity` most likely lost their intended indexes to a day-one authoring oversight, not a deliberate decision, and both are actively used in `ORDER BY`/`WHERE` query paths. A short, targeted migration to re-add them (if the product owner agrees) would be a small, well-scoped follow-up.
3. Given CI is now live and caught a real defect on its first run, **the next push should be treated as a real gate**, not a formality — verify `ruff check .` (full repo, matching CI exactly, per §1's corrected convention) as the standard local pre-push check going forward for this remainder of the programme.
