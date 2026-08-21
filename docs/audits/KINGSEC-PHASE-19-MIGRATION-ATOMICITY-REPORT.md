# KingSec Phase 19 — Migration DDL Atomicity

**Date:** 2026-08-21
**Scope:** Pin down and fix the mechanism behind Phase 18 §3's finding that a
migration failing partway leaves already-applied DDL permanently on disk
while `alembic_version` stays at the old revision.

---

## 1. Baseline, Integrity, CI/Push Status, Pollution Count

- **Branch:** `main`
- **Starting commit:** `9345b71` (Phase 18's report commit) — `origin/main` was
  already at this commit (pushed by something outside this session, per
  Phase 18's own closing notes), so the working tree started even with
  `origin/main`.
- **`git status` at start:** clean except pre-existing, unrelated untracked
  files (`docker-build-log.txt`, `docs/audits/KINGSEC-PHASE-09-*.md`,
  `docs/audits/dead-button-audit*.md`, `kingsec-image.tar`,
  `rebuild-frontend.ps1`) — none touched by this phase, none staged or
  committed.
- **Leftover-container check before the suite run:** none (`docker ps -a`
  empty for any `kingsec*` name).
- **Full suite before any change:** `python -m pytest tests/ -q
  --junitxml=phase19_junit_baseline.xml` → **2884 passed, 0 failures, 0
  skipped**, 159.895s. Matches Phase 18's baseline exactly.
- **Pollution count at start:** `git status --porcelain
  src/kingsec/alembic/versions/` → 0 lines.
- **Commits pushed this phase:** `6789ce4` (fix), `73948c5` (test) — pushed to
  `origin/main` at `9345b71..73948c5`.
- **Pollution count at end:** `git status --porcelain
  src/kingsec/alembic/versions/` → 0 lines, re-checked after the full
  post-fix suite run.

---

## 2. §2 Hypothesis Result — CONFIRMED

**Hypothesis:** pysqlite does not open a transaction before DDL statements;
`CREATE INDEX`/`DROP INDEX`/`CREATE TABLE` commit immediately in autocommit
mode regardless of what SQLAlchemy/Alembic believe they have wrapped.

All three required checks were run and all three confirm the hypothesis.

### 2.1 Connection/engine construction (file:line)

`src/kingsec/alembic/env.py:105-113` (pre-fix), `_engine_from_settings()`:

```python
if resolved_url.startswith("sqlite"):
    engine = create_engine(
        resolved_url,
        connect_args={"check_same_thread": False},
        future=True,
    )
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine
```

No `isolation_level` override anywhere — SQLAlchemy's default pysqlite
handling applies unmodified. `run_migrations_online()` is the only caller of
this function; `run_migrations_offline()` never opens a real connection (see
§4.2).

### 2.2 Tracing an actual migration run

An isolated copy of `alembic.ini` with `[logger_sqlalchemy] level = INFO`
was used to run the real migration `91969658a556` against a database freshly
upgraded to `d1e2f3a4b5c6` (script:
`$CLAUDE_JOB_DIR/tmp/phase19_trace/alembic_traced.ini`). The alembic-level
log (not a script's own inference — Alembic's own runtime) reported:

```
INFO:alembic.runtime.migration:Context impl SQLiteImpl.
INFO:alembic.runtime.migration:Will assume non-transactional DDL.
INFO:alembic.runtime.migration:Running upgrade d1e2f3a4b5c6 -> 91969658a556, rename stale indexes to match models.py
```

Tracing this to source (`.venv/Lib/site-packages/alembic/ddl/sqlite.py:41-47`):

```python
class SQLiteImpl(DefaultImpl):
    __dialect__ = "sqlite"

    transactional_ddl = False
    """SQLite supports transactional DDL, but pysqlite does not:
    see: http://bugs.python.org/issue10740
    """
```

This is Alembic's own, independent documentation of the exact mechanism the
hypothesis describes — not an inference made in this investigation.
`alembic/runtime/migration.py:372-467`'s `begin_transaction()` shows the
consequence directly: for the **outer** call in `run_migrations_online()`
(`with context.begin_transaction(): context.run_migrations()`,
`_per_migration=False`), `transaction_now` evaluates `False` when
`transactional_ddl` is `False`, so it returns `nullcontext()` — **a
complete no-op**. Alembic separately opens a **per-migration** transaction
(`_per_migration=True`, one revision's entire `upgrade()`/`downgrade()`
wrapped in a single `sqla_compat._safe_begin_connection_transaction()` call)
— a real SQLAlchemy-level transaction, which §2.3 shows pysqlite still
does not honor for DDL.

### 2.3 Direct DDL-rollback demonstration

Script: `$CLAUDE_JOB_DIR/tmp/phase19_hypothesis_test.py`, engine constructed
identically to `env.py` (`connect_args={"check_same_thread": False}`, no
`isolation_level`), `echo=True`:

```
=== isolation_level in effect === SERIALIZABLE

=== opening a connection, beginning a transaction, issuing DDL, then ROLLING BACK ===
INFO sqlalchemy.engine.Engine BEGIN (implicit)
INFO sqlalchemy.engine.Engine CREATE TABLE phase19_probe (id INTEGER PRIMARY KEY)
INFO sqlalchemy.engine.Engine CREATE INDEX ix_phase19_probe ON phase19_probe (id)
>>> about to roll back (context manager exit without commit would commit; forcing explicit rollback)
INFO sqlalchemy.engine.Engine ROLLBACK

=== checking whether the table/index survived the rollback ===
INFO sqlalchemy.engine.Engine BEGIN (implicit)
sqlite_master rows matching phase19_probe: [('phase19_probe',), ('ix_phase19_probe',)]
DDL PERSISTED DESPITE ROLLBACK - hypothesis CONFIRMED
```

SQLAlchemy logs `BEGIN (implicit)` before the DDL — bookkeeping at the
Python level that *looks* like a real transaction — but the `CREATE
TABLE`/`CREATE INDEX` survived an explicit `ROLLBACK` on the same
connection. **Confirmed, not refuted.** No investigation-from-evidence
pivot was needed — all three required checks agreed with the named
hypothesis and with Alembic's own source.

---

## 3. Pre-Fix Reproduction, Rebuilt Verbatim

Rebuilt independently in this phase, not reused from Phase 18's own run.

**Setup:** fresh database upgraded to `d1e2f3a4b5c6` (pre-migration head),
then `ix_sso_sessions_provider_id` created by hand (the exact index
`91969658a556` itself creates as operation 31 of 32) to force a name
collision.

**Before the attempt:**
```
account_links indexes: ['ix_account_links_provider', 'ix_account_links_user',
  'sqlite_autoindex_account_links_1', 'sqlite_autoindex_account_links_2']
sso_sessions indexes: ['ix_sso_sessions_provider', 'ix_sso_sessions_provider_id',
  'ix_sso_sessions_user', 'sqlite_autoindex_sso_sessions_1']
alembic_version: d1e2f3a4b5c6
```

**`alembic upgrade head` result:** exit code 1 —
`sqlalchemy.exc.OperationalError: (sqlite3.OperationalError) index
ix_sso_sessions_provider_id already exists`.

**After the failed attempt (pre-fix):**
```
account_links indexes: ['ix_account_links_provider_id', 'ix_account_links_provider_user',
  'ix_account_links_user_id', 'sqlite_autoindex_account_links_1', 'sqlite_autoindex_account_links_2']
sso_sessions indexes: ['ix_sso_sessions_provider_id', 'sqlite_autoindex_sso_sessions_1']
alembic_version: d1e2f3a4b5c6
```

`account_links` fully migrated to its new index names — all 5 of its
operations (which precede the failure point) persisted. `sso_sessions` is
left with **neither** the old names (`ix_sso_sessions_provider`,
`ix_sso_sessions_user` — both dropped) **nor** the new ones (only the
pre-created decoy survives; `ix_sso_sessions_user_id`, operation 32, never
ran) — a schema state matching neither revision. `alembic_version` stayed
at the old revision throughout. This exactly reproduces Phase 18 §3's
finding, rebuilt independently.

---

## 4. §3 Design and Fix

### 4.1 Scope: migration-only, not application-wide

`kingsec-migrate` (`src/kingsec/_migrate.py`) runs `alembic -c <config>
upgrade head` as a subprocess — a live-connection command, never `--sql`.
So the real entry point exclusively exercises `run_migrations_online()`,
never `run_migrations_offline()`. `run_migrations_offline()` doesn't open a
DBAPI connection at all (`context.configure(url=url, literal_binds=True,
...)` just renders SQL text) — no real DDL execution occurs there, so it is
inherently unaffected by this defect and needs no fix.

The fix was scoped to `_engine_from_settings()` in `env.py` — the engine
`run_migrations_online()` builds — leaving `database.py`'s runtime engine
untouched.

### 4.2 Does the runtime engine share the defect? Yes — reported only, not fixed

`src/kingsec/infrastructure/persistence/database.py:86-93` constructs its
engine identically: `create_engine(url, connect_args={"check_same_thread":
False}, future=True)`, no `isolation_level` override. If DDL were ever
executed through this engine inside a transaction the application expected
to roll back, it would exhibit the exact same non-atomic behavior.

The only DDL call site reachable through this engine is
`create_database_engine()`'s companion function (line 124,
`Base.metadata.create_all(engine)`), whose own docstring states: *"Retained
for test fixtures and quick-start scenarios only. Production deployments
MUST use `alembic upgrade head` instead."* This always runs against a fresh,
empty database — there is nothing to roll back to, so the defect is present
at the engine-construction level but not reachable in a way that causes
harm anywhere in the current codebase. Per §3/§6, **this is reported as a
finding, not fixed, in this phase.**

### 4.3 The fix

`src/kingsec/alembic/env.py`, `_engine_from_settings()`:

```python
if resolved_url.startswith("sqlite"):
    engine = create_engine(
        resolved_url,
        connect_args={"check_same_thread": False, "isolation_level": None},
        future=True,
    )
    event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    event.listen(engine, "begin", _emit_explicit_begin)
    return engine
```

with a new handler:

```python
def _emit_explicit_begin(conn: Any) -> None:
    """Issue a real BEGIN so SQLite's transactional DDL support is actually used."""
    conn.exec_driver_sql("BEGIN")
```

`isolation_level=None` puts the raw DBAPI connection into true autocommit,
disabling pysqlite's own implicit-BEGIN heuristic entirely (it stops making
transaction decisions at all — DML included). The `"begin"` event listener
makes SQLAlchemy's transaction boundaries real by issuing `BEGIN` itself:
when Alembic's per-migration `_safe_begin_connection_transaction()` starts a
SQLAlchemy `Connection` transaction, this listener fires and sends a genuine
`BEGIN` to SQLite — so every statement inside that revision's `upgrade()`,
DDL included, now executes inside one real SQLite transaction, and
`ROLLBACK` genuinely undoes all of it. SQLite itself has always supported
transactional DDL; this removes the one thing that was stopping pysqlite
from using it. This is the standard, SQLAlchemy-documented recipe for
working around pysqlite's legacy transaction handling.

Full diff (`git show 6789ce4`) adds 26 lines to `env.py`; no other file in
the fix commit.

### 4.4 Autogenerate and downgrade paths preserved

`_skip_empty_autogenerate_revision` (Phase 16) is untouched and still wired
via `process_revision_directives=` in `run_migrations_online()`'s
`context.configure()` call — the fix only changes the engine, not the
`context.configure()` call. Confirmed empirically in §6/§7 below:
autogenerate on a clean database still produces zero files, and
`downgrade`/`upgrade` round trips (empty and populated) both succeed.

---

## 5. §4 Verification — Every Item

### 5.1 Same forced failure, post-fix — full rollback

Same setup as §3 (fresh db at `d1e2f3a4b5c6`, `ix_sso_sessions_provider_id`
pre-created). `alembic upgrade head` failed identically (`index
ix_sso_sessions_provider_id already exists`, exit 1).

**After the failed attempt (post-fix):**
```
account_links indexes: ['ix_account_links_provider', 'ix_account_links_user',
  'sqlite_autoindex_account_links_1', 'sqlite_autoindex_account_links_2']
sso_sessions indexes: ['ix_sso_sessions_provider', 'ix_sso_sessions_provider_id',
  'ix_sso_sessions_user', 'sqlite_autoindex_sso_sessions_1']
alembic_version: d1e2f3a4b5c6
```

Both tables are back to their exact pre-migration state (`sso_sessions`
additionally carries the manually pre-created decoy, untouched since the
migration never reached it). This is a complete reversal of §3's pre-fix
result for the identical forced failure.

### 5.2 Second, independent failure point (operation 2 of 32, different mechanism)

Fresh db at `d1e2f3a4b5c6`; `ix_account_links_user` (the target of the
migration's *second* operation) was manually dropped beforehand, so the
migration's own `drop_index` re-attempt fails with a different SQLite error
class (`no such index`, not `already exists`). Operation 1
(`drop_index ix_account_links_provider`) succeeds first — this tests
whether even a single already-executed DDL statement gets rolled back.

Result: exit 1, `sqlalchemy.exc.OperationalError: (sqlite3.OperationalError)
no such index: ix_account_links_user`. After the failure:
```
account_links indexes: ['ix_account_links_provider', 'sqlite_autoindex_account_links_1',
  'sqlite_autoindex_account_links_2']
alembic_version: d1e2f3a4b5c6
```
`ix_account_links_provider` — dropped by operation 1 before the failure —
is back. One data point (§5.1) plus this second, mechanistically distinct
one confirms the fix, not a coincidence.

### 5.3 Recovery after rollback (genuine recoverability, not just coherence)

Using §5.1's database: the decoy index (`ix_sso_sessions_provider_id`) was
dropped to remove the forced-failure cause, then `alembic upgrade head` was
re-run: **exit 0**. Final state: `account_links` and `sso_sessions` both
show exactly the new revision's expected index sets
(`ix_account_links_provider_id`/`ix_account_links_provider_user`/
`ix_account_links_user_id`; `ix_sso_sessions_provider_id`/
`ix_sso_sessions_user_id`), `alembic_version = 91969658a556`. The database
is genuinely re-runnable after a rolled-back failure, not merely stuck in a
valid-looking dead end.

### 5.4 Remaining §4 checklist

- **Fresh-database `upgrade head`:** succeeds — covered by
  `TestMigrationUpgrade::test_upgrade_creates_all_tables` (passing, part of
  the 2887-test run below).
- **Downgrade → upgrade round trip, empty:** covered by
  `TestMigrationRoundTrip::test_upgrade_downgrade_upgrade_cycle` (passing).
- **Downgrade → upgrade round trip, populated:** run manually — a fresh db
  upgraded to head, populated with a `job_leases` row and an `account_links`
  row, then `downgrade base` (exit 0) and `upgrade head` (exit 0) both
  succeeded cleanly with the fix in place (downgrade base necessarily drops
  the data along with the tables — that is `downgrade base`'s documented
  behavior, not a defect).
- **Autogenerate still produces no file:** confirmed —
  `TestMigrationAutogenerate::test_autogenerate_on_clean_state_produces_no_changes`
  passes (isolated config, zero files in both the scratch and real
  `versions/` directories).
- **`git status --porcelain src/kingsec/alembic/versions/` empty after a
  full suite run:** confirmed, 0 lines, both before and after the full
  2887-test run.
- **Wheel determinism:** `python -m build --wheel` produced a wheel packaging
  exactly the 32 files `git ls-files
  src/kingsec/alembic/versions/*.py` tracks (byte-identical filename sets,
  confirmed via `diff --strip-trailing-cr`; the only earlier diff was a
  CRLF/LF artifact from a Windows-generated file list). Scratch build
  directory removed afterward — not committed.
- **Regression test:** added — see §6.

---

## 6. Regression Test Added

`tests/integration/test_alembic_migrations.py`, new class
`TestMigrationAtomicity` (commit `73948c5`), following
`TestMigrationWithPopulatedUniqueConstrainedData`'s pattern:

- `test_forced_failure_near_end_rolls_back_entire_migration` — §5.1's
  scenario as a permanent test: pre-create `ix_sso_sessions_provider_id`,
  assert the migration fails, assert `alembic_version` is unchanged, assert
  `account_links` and `sso_sessions`'s full index dictionaries
  (`{name: is_unique}`) are byte-for-byte unchanged from before the attempt.
- `test_forced_failure_near_start_rolls_back_entire_migration` — §5.2's
  scenario: pre-drop `ix_account_links_user`, assert the different SQLite
  error, assert `account_links`'s indexes (including the one operation that
  ran before the failure) are unchanged.
- `test_upgrade_succeeds_cleanly_after_a_rolled_back_failure` — §5.3's
  scenario: force the failure, remove its cause, assert `upgrade head` then
  succeeds and produces exactly the new revision's expected indexes and
  stamp.

---

## 7. Gate Results and Suite Counts

All gates below use **`ruff check .`** — the full-repo, CI-matching
invocation — per §0.7, never the tracked-files-only variant.

| Gate | Command | Result |
|---|---|---|
| Lint (Ruff) | `ruff check .` | **All checks passed.** |
| Types (mypy) | `mypy src` | **Success: no issues found in 585 source files** (local, Windows) — see §9 for the CI/Linux divergence |
| Architecture (import-linter) | `lint-imports` | **Contracts: 3 kept, 0 broken** (Hexagonal layering, Domain purity, Application-knows-domain-only) |
| Security (Bandit) | `bandit -q -r src` | **exit 0, 0 issues** |
| Security (pip-audit) | `pip-audit` | **exit 1 — 9 known vulnerabilities in 3 packages** (`mcp`, `pip`, `pypdf2`) — pre-existing, no dependency touched by this phase; see §12/§13 |
| Full suite (pre-fix baseline) | `pytest tests/ --junitxml=...` | **2884 passed, 0 failures, 0 skipped**, 159.9s |
| Full suite (post-fix) | `pytest tests/ --junitxml=...` | **2887 passed, 0 failures, 0 skipped**, 161.3s (2884 + 3 new atomicity tests) |

`pip-audit`'s findings are unrelated to migration atomicity — no dependency
version changed in this phase. Reported per the evidence standard, not
fixed; scoped for Phase 20 (§13).

---

## 8. §5 Full CI Pipeline Result, Step by Step — First End-to-End Run

Two CI runs are relevant here. Both are genuine, independently triggered
`main` pushes — this is the **first time in the programme's history CI has
progressed past the Lint (Ruff) step**, confirming Phase 18's fix
(`a9e65e6`) actually worked end-to-end, not just locally.

### 8.1 Run `32479925859` (Phase 18's push, `9345b71`, pre-existing at start of this phase)

| Job | Result |
|---|---|
| Frontend Quality Gates | ✅ passed, 1m58s |
| Quality Gates (3.11) | ❌ failed at **Types (mypy)**, 45s |
| Quality Gates (3.12) | ❌ failed at **Types (mypy)**, 44s |
| Quality Gates (3.13) | ❌ failed at **Types (mypy)**, 51s |

Lint (Ruff) **passed** on all three — direct confirmation Phase 18's fix
holds in CI, not just locally. mypy verbatim (identical across all three
Python versions):

```
src/kingsec/infrastructure/licensing/parser.py:155: error: Module has no attribute "OpenKey"  [attr-defined]
src/kingsec/infrastructure/licensing/parser.py:156: error: Module has no attribute "HKEY_LOCAL_MACHINE"  [attr-defined]
src/kingsec/infrastructure/licensing/parser.py:159: error: Module has no attribute "QueryValueEx"  [attr-defined]
src/kingsec/infrastructure/licensing/parser.py:161: error: Module has no attribute "CloseKey"  [attr-defined]
src/kingsec/infrastructure/plugin/sandbox.py:104: error: Unused "type: ignore" comment  [unused-ignore]
Found 5 errors in 2 files (checked 585 source files)
```

### 8.2 Run `32481262113` (this phase's push, `73948c5`)

| Job | Result |
|---|---|
| Frontend Quality Gates | ✅ passed, 2m1s |
| Quality Gates (3.11) | ❌ failed at **Types (mypy)**, 43s |
| Quality Gates (3.12) | ❌ failed at **Types (mypy)**, 53s |
| Quality Gates (3.13) | ❌ failed at **Types (mypy)**, 51s |

Identical shape and identical errors to §8.1 — this phase's changes
(`env.py`, `test_alembic_migrations.py`) touch neither `licensing/parser.py`
nor `plugin/sandbox.py`, so the mypy failure is unchanged and unrelated to
Phase 19's work. Lint (Ruff) passed again.

**Because the job stops at Types (mypy), Architecture (import-linter),
Security (Bandit), Security (pip-audit), and Test (pytest) have still never
executed in CI** — one step further than Phase 18 found (which stopped at
Lint), but still not the full pipeline. Every claim about those four gates
continues to rest on local runs (§7).

### 8.3 Environment difference identified

`licensing/parser.py:150-162` wraps its `winreg` usage in a runtime
`try: import winreg ... except (ImportError, OSError, FileNotFoundError):
pass` — correct at runtime (Linux raises `ImportError`, caught cleanly).
But mypy statically type-checks the `import winreg` line regardless of the
surrounding `try/except`, and typeshed's `winreg` stub only declares
`OpenKey`/`HKEY_LOCAL_MACHINE`/`QueryValueEx`/`CloseKey` under a
`sys.platform == "win32"` guard. **This local development machine is
Windows** (`mypy src` here reports 585/585 clean), so this divergence was
invisible locally in every prior phase's own gate run — CI's Linux runners
are the first environment in this programme to actually execute mypy under
the platform the failure requires. `sandbox.py:104`'s `# type:
ignore[attr-defined]` on `resource.getrusage(...)` being reported "unused"
is consistent with the same story: `resource` is a Linux-only stdlib module
that resolves cleanly on CI's Linux runners, making the ignore comment
(evidently added for a context where it didn't resolve) genuinely
unnecessary there.

Not fixed in this phase — out of scope (migration atomicity), unrelated
files, and not trivial enough to fix blind (the correct fix requires either
a `sys.platform`-conditional mypy override in `pyproject.toml` or
restructuring the `winreg` import so mypy's platform-aware narrowing
applies, and confirming the fix doesn't just trade a CI-only failure for a
local-only one). Recommended for Phase 20 (§13).

---

## 9. Docker Rebuild, Startup, and Fresh Volume Stamp

**Build:** `docker compose build --progress=plain`, run against the
committed working tree (`73948c5`). Took 3758.5s for the pip-install layer
alone (this session's network throttling/a mid-build disruption, not a
Docker or code issue) but completed cleanly: `Image kingsec:2.0.0 Built`.

**Startup, fresh volume:** a new named volume (`kingsec-data-phase19`) and a
container from the freshly built image. First start surfaced a real but
**pre-existing, unrelated** issue: the container crashed *after* migrations
completed but *before* the HTTP server started, with `ConfigError:
KINGSEC_SECRETS__ENCRYPTION_KEY is not set` — this environment's `.env`
supplies that secret locally, masking the gap outside Docker, consistent
with the standing memory note that KingSec has no default for these three
secrets. Restarted the same container against the same volume with all
three secrets generated fresh (`KINGSEC_SECRETS__ENCRYPTION_KEY`,
`KINGSEC_JWT__SECRET_KEY`, `KINGSEC_SECRETS__API_KEY_PEPPER`, per
`.env.example`) — not a Phase 19 fix, just what was needed to get the
container far enough to check the app layer, not only the migration layer.

**Migration log, this container, full chain to head:**
```
INFO:alembic.runtime.migration:Will assume non-transactional DDL.
INFO:alembic.runtime.migration:Running upgrade  -> 095f30b10a04, initial schema
...
INFO:alembic.runtime.migration:Running upgrade d1e2f3a4b5c6 -> 91969658a556, rename stale indexes to match models.py
```
All 32 migrations applied cleanly against a fresh, empty volume — including
`91969658a556` with the fix in place.

**Health check:** Docker's own `HEALTHCHECK` reported `Up ... (healthy)`;
the access log recorded three independent `GET /api/v1/health` requests, all
`status_code=200`.

**Fresh volume's `alembic_version` and index state, read directly via a
throwaway `python:3.12-slim` container mounting the same volume (bypassing
the app entirely):**
```
alembic_version: [('91969658a556',)]
account_links indexes: ['ix_account_links_provider_id', 'ix_account_links_provider_user',
  'ix_account_links_user_id', 'sqlite_autoindex_account_links_1', 'sqlite_autoindex_account_links_2']
sso_sessions indexes: ['ix_sso_sessions_provider_id', 'ix_sso_sessions_user_id',
  'sqlite_autoindex_sso_sessions_1']
```
Matches the new revision's expected schema exactly.

**Teardown:** container and volume both removed; confirmed via `docker ps -a`
and `docker volume ls` that neither `kingsec-phase19` nor
`kingsec-data-phase19` remain, and nothing is left listening on port 8765.

---

## 10. Files Changed and Commit Hashes

| Commit | Files | Summary |
|---|---|---|
| `6789ce4` | `src/kingsec/alembic/env.py` (+26/-1) | The atomicity fix: `isolation_level=None` + explicit `BEGIN` event listener, scoped to the migration engine |
| `73948c5` | `tests/integration/test_alembic_migrations.py` (+136) | `TestMigrationAtomicity` — three regression tests |

Both pushed to `origin/main` (`9345b71..73948c5`).

---

## 11. What This Phase Does NOT Fix

- **Finding 5's product decision** (Option A/B/C, Phase 15 §7) — still open,
  still the product owner's call.
- **The two missing indexes** (`asset_history.timestamp`,
  `exposures.severity`) — Phase 18 §4 evidenced these as an accidental
  day-one omission; still awaiting a product-owner decision. Not
  re-added.
- **`database.py`'s runtime engine sharing the same non-atomic-DDL
  construction** (§4.2) — reported only, per explicit instruction. Its only
  DDL call site is test-fixture/quick-start-only and runs against a fresh
  empty database, so the defect is present but not currently reachable in a
  harmful way.
- **The Linux/Windows mypy divergence** (§8.3, `licensing/parser.py`,
  `plugin/sandbox.py`) — pre-existing, unrelated to migration atomicity, now
  independently confirmed to block CI at the second pipeline step on two
  separate pushes.
- **`pip-audit`'s 9 findings** (`mcp`, `pip`, `pypdf2`) — pre-existing, no
  dependency touched.
- The existing stale volumes — not touched, not `stamp`ed.
- Findings 6, 7, 8; Phase 11's carried observations (unpinned `pip`, no
  scanner-binary version guidance — the `pip` finding above is the same
  carried observation, now additionally confirmed by `pip-audit` rather than
  just noted); Phase 12's carried observation (`diagnostics.py`'s hardcoded
  probe); Phase 14 §5's residual credential-exfiltration risk; Phase 16's
  two carried notes (builder-stage `.git` layer,
  `_skip_empty_autogenerate_revision` in production `env.py`); Phase 17
  §10's build-caching suggestion; frontend work.

---

## 12. Recommended Phase 20 Scope

1. **Fix the CI mypy blocker** (§8.3) — the pipeline has now failed at Lint
   (Phase 18), then at Types/mypy (this phase, twice) and never gone
   further. Import-linter, Bandit, pip-audit, and pytest have *never*
   executed in CI. This is the single highest-leverage fix available: it
   would be the first time the full pipeline runs end-to-end.
2. **Address `pip-audit`'s 9 findings** — bump `mcp`, `pip`, and `pypdf2` to
   their fixed versions (§7), closing out Phase 11's carried pip
   observation with an actual version bump rather than just a note.
3. Continue carrying forward Finding 5, the two missing indexes, and the
   other explicitly out-of-scope items from §11 until a product-owner
   decision or a dedicated phase addresses them.
