# KingSec — Remediation Status

Tracks progress against `docs/REMEDIATION-PLAN.md`. Updated at the end of every phase.

---

## Phase 0 — Green baseline

**Branch:** `fix/phase-0-green-baseline`
**Status:** COMPLETE — acceptance criteria met, awaiting go-ahead to merge/push and to start Phase 1.

### Correction to the audit (verified before starting)

`docs/REMEDIATION-PLAN.md`'s claim that "anomalous dependency version pins" (Inventory Risk #5) is a false positive was independently re-verified:

```
$ pip index versions fastapi
fastapi (0.141.1)
Available versions: 0.141.1, 0.141.0, ...
  INSTALLED: 0.139.0
  LATEST:    0.141.1

$ pip index versions cryptography
cryptography (50.0.1)
...
  INSTALLED: 50.0.0
  LATEST:    50.0.1

$ pip index versions starlette
starlette (1.6.0)
...
  INSTALLED: 1.3.1
  LATEST:    1.6.0
```
Confirmed: all three are real, current releases. Risk #5 is struck.

### Task A — Fixed the ORDER BY / tied-timestamp determinism defects

Root cause confirmed before fixing, and it was more specific than "just add a tiebreaker" — two distinct classes of bug:

1. **`test_list_jobs_newest_first` (×2 — in-memory and DB-backed) and, discovered while verifying, `TestFindOldestPending::test_returns_oldest_pending`**: every list/pagination path that ordered by `created_at` alone left tie order undefined when two records were created within the same clock tick (this machine's `datetime.now(UTC)` resolution is coarse enough that this reliably happens).

   - `src/kingsec/application/jobs.py` (`InMemoryJobService`): added a private, monotonic insertion-sequence counter (`self._sequence`), used as the tiebreaker in `list_jobs()` and `find_oldest_pending()`. A random UUID (the job's own `id`) cannot serve this purpose — it carries no relationship to insertion order — so a genuine sequence counter was added instead of literally following the plan's `ORDER BY created_at DESC, id DESC` example.
   - `src/kingsec/infrastructure/persistence/repositories/job.py` (`SQLAlchemyJobRepository.list()`): added `text("scan_jobs.rowid DESC")` as a secondary sort key after `created_at DESC`. SQLite's implicit `rowid` is a genuine monotonic insertion counter; `id` (also a random UUID here) still can't serve as one. This was chosen over adding a new schema column + migration, since Phase 0's scope explicitly excludes refactors and this fully resolves the defect without one. If the database backend ever changes away from SQLite, this specific line would need revisiting — noted for whoever picks that up.
   - `src/kingsec/application/services/persistent_job_service.py` (`find_oldest_pending`): this one surfaced only while re-running the full suite after the other fixes — imposing a deterministic tie order on `list()` inadvertently exposed a *pre-existing* latent bug in `find_oldest_pending()`'s own `min(pending, key=created_at)`, which picks whichever tied row `list()` happens to return first. Fixed by using `list()`'s own (now-deterministic, newest-first) ordering directly: the oldest pending job is `pending[-1]`, not a separate `min()` call.

2. **`test_cancel_pending_job`** (`cancelled.updated_at > cancelled.created_at`): a *different* defect — not a list ordering issue at all, but two separate `datetime.now(UTC)` calls (one at job creation, one at cancellation) landing in the same clock tick. Fixed with a new `next_timestamp(after)` helper in `jobs.py`: reads the real clock, and only if that read is not strictly after `after` does it fall back to `after + 1 microsecond`. Real elapsed time is always used when it has genuinely advanced; the fallback only ever fires on an actual tie. Applied to both `InMemoryJobService` and `PersistentJobService`'s `cancel_job`/`transition_job`.

**Scope decision, stated explicitly rather than silently applied or silently skipped:** a grep across the persistence layer found the same "`order_by` on a timestamp column alone" pattern in roughly 30 other repositories (assessments, assets, audit events, copilot, dead letters, identity providers, licenses, monitoring, organizations, playbooks, reports, threat intelligence, workers, users, job queue). None of them have a failing test today. Per this phase's own scope ("the 4 failing tests, CLI argument parsing... No refactors. No unrelated file changes"), I did not touch any of them. Recommend a dedicated future phase if this class of bug should be swept codebase-wide — it would be a large, independently-reviewable change, not a Phase 0 side effect.

### Task B — Fixed `test_progressive_lockout_duration`

The plan's initial hypothesis (pure clock-resolution noise) turned out not to be the actual defect — investigated and found something more specific:

`AccountLockoutService._AttemptRecord.clear()` was resetting `lockout_count` to `0` on every call. Per the class's own usage contract, `clear()` is called on every *successful* login. Resetting the escalation counter there means a single successful login — even one unrelated success sandwiched between repeated lockout episodes — silently resets the "progressive" delay back to its shortest tier (60s), for every account, forever. The delay tiers themselves (`60/120/300/600`, keyed off `lockout_count`) were already a deterministic function of the count, exactly as the plan wanted — the count just wasn't being preserved across a clear.

**Fix:** `clear()` now resets `failures` and `lockout_until` (so `is_locked_out` correctly returns to `False` — verified against the existing `test_clear_resets_lockout`, unaffected) but leaves `lockout_count` untouched. The counter now only fully resets when a record is evicted after a full `lockout_window` of no further failures (`AccountLockoutService._evict`, unchanged) — verified against the existing `test_eviction_cleans_old_records`, also unaffected.

With this fix, `second_retry` (120s tier) vs `first_retry` (60s tier) differ by a full minute — the assertion no longer depends on clock resolution at all; no clock injection was needed.

**Security behaviour: net stronger, not weaker.** Before: an attacker who occasionally lets a login succeed (or simply waits) resets their own escalation to the shortest lockout every time. After: escalation persists across intervening successes/clears, exactly matching the class's own docstring ("Lockout duration increases with repeated lockouts").

**Important scoping note:** `AccountLockoutService` is defined and fully tested, but **grep confirms it is not imported or instantiated anywhere outside its own module** (`infrastructure/security/lockout.py` + `infrastructure/security/__init__.py`'s export list). The real, production login path (`application/use_cases/login.py`) uses a separate, DB-backed mechanism — `CheckAccountLockout` + a `lockout_repo` reading the `account_lockouts` table. So this fix changes no live authentication behaviour today; it corrects a real defect in code that exists, is tested, and would matter the moment it's wired in (or reused elsewhere), but isn't reachable in production right now. Flagging this precisely rather than either overstating or ignoring it. The DB-backed mechanism was not investigated for an analogous defect — out of scope, no failing test covers it.

### Task C — CLI argument parsing

- `src/kingsec/__main__.py` (`kingsec`): added `argparse` with `--host`, `--port`, and (via `action="version"`) `--help`/`-h` and `--version`. `--host`/`--port`, when passed, set the corresponding `KINGSEC_SERVER__HOST`/`KINGSEC_SERVER__PORT` environment variable *before* `create_wired_application()` runs — routing the override through the exact same settings/validation path an env-var-supplied value already goes through, so the existing wildcard-bind guardrail (`KINGSEC_SERVER__ALLOW_EXTERNAL_BIND`) applies identically regardless of how the value arrived. With no flags, behaviour is unchanged.
- `src/kingsec/_migrate.py` (`kingsec-migrate`): had no argument parsing at all; added `argparse` with `--version` (and free `--help`/`-h`).
- `src/kingsec/_bootstrap.py` (`kingsec-bootstrap`): already had `argparse` (so `--help` already worked); added `--version`.

### ACCEPTANCE — all TESTED, commands and results below

```
$ uv run pytest -q
3920 collected, 3920 passed... (see below)
duration: 472s
exit code: 0
```
Ran twice: the first run (472s+130s across two invocations) caught the `find_oldest_pending` defect above; after fixing it, a second full fresh run passed completely clean: **0 failed, 0 skipped, 0 errors, exit 0.** The 4 tests that were failing at the start of this phase, plus the newly-added regression test, were additionally re-run in isolation 5x each with zero flakes.

```
$ uv run ruff check .
All checks passed!
```

```
$ uv run mypy src
Success: no issues found in 598 source files
```

```
$ uv run kingsec --help
usage: kingsec [-h] [--version] [--host HOST] [--port PORT]
...
exit code: 0, no port bound (confirmed via netstat)
```

```
$ uv run kingsec --version
kingsec 2.0.0
exit code: 0
```
(Note: `uv run` re-resolves/rebuilds the local editable install after source edits — the first invocation after a change took ~30s; subsequent ones were 5-7s. Not a defect in the CLI code itself; confirmed by re-running the same command and seeing it drop to normal speed once uv's cache was warm.)

Also verified: `kingsec-migrate --help`/`--version`, `kingsec-bootstrap --help`/`--version` all exit 0 with correct output. Verified `--host`/`--port` overrides work end-to-end: started the server against an isolated, migrated, throwaway data directory with `--port 18766` (never touching the real local `~/.kingsec`), confirmed via its own startup log that it bound `127.0.0.1:18766` as instructed, then stopped it.

**Regression test added:** `tests/integration/persistence/test_persistent_job_service.py::TestListJobs::test_list_jobs_tiebreaks_identical_created_at_by_insertion_order` — forces two jobs to share an identical `created_at` directly (not relying on real clock timing to coincidentally tie), then asserts order. Verified this test **fails deterministically (5/5 runs)** against the pre-fix query (temporarily reverted via `git stash`, tested, restored via `git stash pop` — never left uncommitted mid-revert) and **passes deterministically (3/3 runs)** against the fix.

### Git state

```
$ git status --short
 M src/kingsec/__main__.py
 M src/kingsec/_bootstrap.py
 M src/kingsec/_migrate.py
 M src/kingsec/application/jobs.py
 M src/kingsec/application/services/persistent_job_service.py
 M src/kingsec/infrastructure/persistence/repositories/job.py
 M src/kingsec/infrastructure/security/lockout.py
 M tests/integration/persistence/test_persistent_job_service.py
?? docs/PRODUCT-INVENTORY.md      (pre-existing, unrelated to this phase — not staged)
?? docs/REMEDIATION-PLAN.md       (pre-existing, unrelated to this phase — not staged)

$ git diff --stat
 8 files changed, 163 insertions(+), 23 deletions(-)
```

Staged and committed explicitly by path (no `git add .`/`git add -A`) — commit contains exactly the 8 files above. `docs/PRODUCT-INVENTORY.md` and `docs/REMEDIATION-PLAN.md` were already untracked in the working tree before this phase started and are unrelated to Phase 0's scope; left untouched.

**Not pushed.** The branch exists locally only; push/merge is a separate decision for you to make.

### What's next

Per the plan's own rule ("Do not start a phase until the previous one's acceptance criteria are met and committed") and this session's explicit instruction, **Phase 1 has not been started.** Waiting for the go-ahead.

---

## Backlog (logged, not fixed — flagged during Phase 1 setup)

1. **BUG: a `KINGSEC_STORAGE__DATA_DIR` override that fails to resolve silently falls back to the default path instead of failing loudly.** Discovered the hard way during Phase 1 setup: an env-file `source` with an unquoted path containing spaces silently dropped the override, and `kingsec-migrate` ran against the real `~/.kingsec/kingsec.db` instead of the intended isolated directory. The settings layer should fail closed (raise, not silently substitute a default) when an explicitly-set value for a security/isolation-relevant path can't be applied — same philosophy as the existing secret-placeholder guardrail. Not fixed — out of scope for Phase 1.
2. **Two account-lockout implementations exist; the one covered by tests (`AccountLockoutService`, fixed in Phase 0) is not the one the live login path actually uses** (`CheckAccountLockout` + a DB-backed `lockout_repo`, reading the `account_lockouts` table). Phase 0's fix changed no live behavior as a result. Whether the DB-backed mechanism has an analogous escalation-reset defect is unknown — not investigated. Move to Phase 3 scope (auth hardening).
3. **Phase 0 added only 1 regression test for 6 fixed defects.** Missing dedicated regression tests for: the `find_oldest_pending` tie-order fix (both `InMemoryJobService` and `PersistentJobService` variants), and the `AccountLockoutService.clear()` escalation-preservation fix (beyond the one pre-existing test it was verified against, `test_progressive_lockout_duration`, no *new* test was added asserting escalation survives a clear specifically). Should be added before this class of defect is considered closed out.
4. **Unconfirmed: is the `rowid` tiebreaker in `SQLAlchemyJobRepository.list()` actually safe long-term?** It relies on SQLite's implicit `rowid` being monotonically increasing for this table. Not yet confirmed whether `scan_jobs` is declared with `AUTOINCREMENT` (which prevents rowid reuse after deletes) or is a plain rowid table (where SQLite *can* reuse a deleted row's rowid for a later insert, which would silently reintroduce the exact tie-order bug this was meant to fix, just under a different trigger condition). Needs verification before relying on this fix indefinitely.
