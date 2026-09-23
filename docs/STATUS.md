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
2. ~~Two account-lockout implementations exist...~~ **RESOLVED, Phase 3.** Confirmed the live login path uses `CheckAccountLockout` + `RecordFailedAuthentication`/`RecordSuccessfulAuthentication` (the DB-backed `LockoutRepository`/`account_lockouts` table family) — not `AccountLockoutService`. Definitive answer on the open question: the live path does **not** have an analogous escalation-reset defect, because it never implemented escalation in the first place — `AccountLockout` (`domain/rate_limit.py`) has no field to record a prior-lockout count, so `RecordFailedAuthentication` always applies the same fixed `lockout_duration_seconds`. `AccountLockoutService` deleted (in-memory, single-process, structurally incompatible with the DB-backed live design — see Phase 3 section below and the carried-over-conclusion pattern's fifth instance above). No second lockout implementation remains.
3. **Phase 0 added only 1 regression test for 6 fixed defects.** Missing dedicated regression tests for: the `find_oldest_pending` tie-order fix (both `InMemoryJobService` and `PersistentJobService` variants), and the `AccountLockoutService.clear()` escalation-preservation fix (beyond the one pre-existing test it was verified against, `test_progressive_lockout_duration`, no *new* test was added asserting escalation survives a clear specifically). Should be added before this class of defect is considered closed out.
4. **Unconfirmed: is the `rowid` tiebreaker in `SQLAlchemyJobRepository.list()` actually safe long-term?** It relies on SQLite's implicit `rowid` being monotonically increasing for this table. Not yet confirmed whether `scan_jobs` is declared with `AUTOINCREMENT` (which prevents rowid reuse after deletes) or is a plain rowid table (where SQLite *can* reuse a deleted row's rowid for a later insert, which would silently reintroduce the exact tie-order bug this was meant to fix, just under a different trigger condition). Needs verification before relying on this fix indefinitely.
5. **BUG (found during Phase 5's claim audit): `AssessmentConcurrencyPort.try_reserve_slot()` is built but never called.** KSEC-87-02's own docstring says this port exists specifically because `max_concurrent_assessments` "existed as configuration but was never enforced anywhere." The atomic, TOCTOU-safe mechanism it built to fix that is itself unwired — grepped every call site of `try_reserve_slot(` across the whole codebase; it appears only in comments/docstrings in three files, never an actual call, and `AssessmentConcurrencyPort` is registered in the DI container but never resolved into `CreateAssessment`/`SubmitAssessment`/any use case. `max_concurrent_assessments` is not enforced anywhere in the running application today — the exact defect KSEC-87-02 was supposed to close. Not fixed — out of scope for Phase 5 (docs-only). Full detail: `docs/CLAIM-AUDIT.md` item 7.
6. **BUG (found during Phase 5's claim audit): a placeholder CVE id in the real compliance mapping table.** `application/compliance/mapper.py`'s keyword-to-control map has two entries mapping the `{"unpatched","outdated"}` and `{"cve","known","vulnerability"}` keyword sets to `ComplianceFramework.CVE` with the literal control id `"CVE-2025-1234"` - a placeholder, not a real CVE. Any finding whose title/description matches those keywords would cite a fabricated CVE number as a real mapped control in a compliance report. Not fixed - out of scope for Phase 5 (docs-only). Full detail: `docs/CLAIM-AUDIT.md` item 4.

---

## Phase 1 — End-to-end proof

**Branch:** `chore/phase-1-e2e-evidence` (based on `fix/phase-0-green-baseline`)
**Status:** COMPLETE — acceptance criteria met, awaiting go-ahead to proceed. **Full details in `docs/E2E-EVIDENCE.md`** — this section is a summary only.

### What happened

- Installed 5 previously-absent scanner binaries this phase (with explicit per-tool approval): nuclei, ffuf, gobuster, amass (all now genuinely working), and OWASP ZAP (installed, but confirmed **not actually invokable** by KingSec's scanner-execution pattern on Windows — see E2E-EVIDENCE.md Defect 7). Nikto could not be installed — the downloaded Perl script was quarantined by Windows Defender; not worked around.
- Ran DVWA (`vulnerables/web-dvwa`) locally in Docker, loopback-only, as the scan target.
- **A real mistake happened and was corrected**: an env-file `source` with an unquoted path (containing spaces) silently dropped a `KINGSEC_STORAGE__DATA_DIR` override, and `kingsec-migrate` ran against the real `~/.kingsec/kingsec.db` instead of the intended isolated directory. Caught immediately; the real database was backed up (`kingsec.db.bak-phase1`) before proceeding; confirmed via direct query that no data was lost (the 3 migrations applied were additive schema changes only, and the one pre-existing assessment row was untouched). Corrected the approach per explicit instruction for the remainder of the phase: never `source` an env file again; every env var passed explicitly per-command, all paths quoted. Re-verified the isolation this way — proved the override actually resolved (read-only check) *before* any write, then confirmed post-migration that the new DB existed at the isolated path and the real DB's mtime was unchanged.
- Ran 4 real assessments end-to-end (register → login → create → start → poll to completion → generate report → download real PDF) against the real, isolated KingSec instance: Quick Host Scan (ip target), Web Application Scan (url target), Full Assessment (url target), and a supplementary Full Assessment (ip target) added to confirm a hypothesis formed mid-phase.
- Found **8 numbered defects/observations**, all TESTED with real command output or real artifacts — most significantly: HTML reports are completely unreachable in any real deployment (hardcoded default, never wired to config); scanners incompatible with an assessment's target type are left permanently `"pending"` instead of `"skipped"`, and this does not block the assessment from reaching `"completed"`; the report's own "coverage incomplete" warning only accounts for `"failed"` scanners, so a report can look clean while 6 of 9 configured scanners never ran at all.
- **No web-application-layer scanner (Gobuster/FFUF/Nuclei/ZAP/Nikto) ever completed a scan against DVWA in this environment**, for a mix of genuine environment gaps (no wordlist, no templates, ZAP's Windows packaging, Nikto blocked by Defender) — meaning **zero Critical/High/Medium findings were observed in this phase**, despite DVWA being specifically designed to have them. This is an important, honest limit on what Phase 2's scoring-formula calibration can be checked against using only this phase's data.

### ACCEPTANCE

- [x] `docs/E2E-EVIDENCE.md` exists with a real severity distribution table (Section 4)
- [x] At least one real PDF report exists and has been opened and inspected — two were (60,266-byte and 34,588-byte PDFs, both read page-by-page)
- [x] Actual run times recorded for 4 profiles (exceeds the minimum of 3)
- [x] Defect list produced — 8 numbered items, all TESTED
- [x] `docs/STATUS.md` updated (this section)

### Cleanup

The isolated KingSec server, the DVWA container, and the isolated data directory were torn down at the end of this phase (server process stopped; `dvwa-p1-target` container removed). The real `~/.kingsec/kingsec.db` remains as migrated (see above — additive, non-destructive, confirmed) plus its `kingsec.db.bak-phase1` backup, which was **not** removed and is left for you to delete once you've confirmed you're satisfied with the outcome.

### What's next

Per the plan's own rule and this session's explicit instruction, **Phase 2 has not been started.** `docs/E2E-EVIDENCE.md` is ready to be reviewed — per the plan's own text, "if a real scan does not produce a coherent report, the remediation plan changes and Phase 2 waits." A real scan *did* produce a coherent report (twice), so that condition is met — but the severity-range limitation above (no Critical/High/Medium data) is worth weighing before Phase 2's scoring-model calibration step specifically.

---

## Phase 2A — Honest execution and coverage

**Branch:** `fix/phase-2a-honest-coverage` (based on `chore/phase-1-e2e-evidence`)
**Status:** CLOSED — APPROVED. All acceptance criteria (including 2A-b, below) verified against the rendered PDF. Phase 2B not started.

### The carried-over-conclusion pattern (read this before starting Phase 2B)

Three separate times in this phase, a conclusion carried over from before a context reset was reported as settled without being re-verified in the current session, and each time it turned out to be wrong:

1. The wordlist check — reported "no fix needed" in a way that read as a claim about the code's whole history, when the code had in fact changed earlier in the same phase.
2. The reference-case regression test's scanner count — reported as "3 of 9 succeed," a figure that only ever existed in a fabricated stub-registry fixture; the real, evidence-matched number was 1 of 9.
3. **FIX 6** — the Step 2 report claimed it was "already correct from before the context reset; no changes needed." This was false: FIX 6 had only ever adjusted `action_required` and appended a coverage caveat to the verdict headline. It never touched the report's score, score band, gauge color, or headline ordering — which is exactly why the Run #4 defect reproduced itself on the report's own page 2 (a "SOUND" band and "generally sound standing" narrative next to a coverage warning nobody reading that page would see), requiring the separate Phase 2A-b fix below.

None of these were caught by pytest, ruff, or mypy — all three passed every automated gate. They were caught by manual review against independent sources (another document stating the same fact, or a human looking at the actual rendered PDF). The lesson, now codified in `CLAUDE.md`'s Verification honesty section: a conclusion carried over from before a context reset is unverified by default, regardless of how confidently it was stated, until it is re-checked against the current code in the current session.

**A fourth instance recurred in Phase 2B Task 2:** a failing `tests/integration/test_alembic_migrations.py` line observed mid-session was reported as "confirmed pre-existing, unrelated" — stated as settled without being checked against a clean baseline. It was not pre-existing: verified via an isolated `git worktree` at the branch's own committed HEAD (738ce02) plus the working tree itself, both runs green, 13/13 passed, no reproduction anywhere. The individual explanation for why it appeared mid-session is not the useful part of this record (most likely a transient artifact of accumulated alembic-pollution files from an earlier full-suite run in the same session — see the pollution bug logged above — but that is a guess, not a finding); the pattern entry is: a FAILED line was characterized as pre-existing without verification, the same shape as items 1 and 2 above, not a new or different failure mode.

**A fifth instance, a different mechanism but the same shape, closed in Phase 3:** Phase 0's Task B fix (`AccountLockoutService.clear()` preserving `lockout_count` across a clear, so a single successful login can't reset progressive-lockout escalation) was reported at the time as "net stronger security behaviour." That was true of the code fixed — and Phase 0 said so precisely, flagging in the same breath that the fix "changes no live authentication behaviour today" since `AccountLockoutService` was never wired into the real login path. The claim was accurate as written. What went wrong is what happened to it afterward: "we fixed the lockout escalation bug" sat in this file's record for six weeks, and by the time Phase 3 investigated it, that shorthand had drifted into something read as true of the product, when it was only ever true of a class the product does not execute. This is not a criticism of the Phase 0 fix itself, which was correct and is now proven, via Phase 3's own pinning test, to be architecturally inapplicable to the live path rather than merely unwired — `AccountLockoutService` was in-memory, single-process, structurally incompatible with the DB-backed live mechanism regardless of wiring. The lesson is the same as items 1-4: a precisely-scoped claim, true when written, is not self-maintaining — it needs to be re-stated at the point where a reader would reasonably generalize it, not just left to accumulate. `AccountLockoutService` is deleted as of Phase 3 (see that section below); the live path's real, current, fixed-duration behavior is now pinned by `test_live_lockout_duration_is_fixed_not_progressive`.

**A sixth instance, in Phase 4, inverts the mechanism again:** Phase 4's own Step 1 investigation (reported in-session, not yet written to a persisted document) had already found and verified: `domain/authorization.py` - a frozen value object with `authorized_by`, `authorized_at`, `scope` - persisted on `AssessmentORM` (`infrastructure/persistence/models.py:43-45`) as `authorization_scope`. Later in the same phase, checking whether that field could source a migration backfill, the check re-grepped only `domain/assessment.py` (the aggregate's own module) for "scope", found nothing there, and reported the source might not exist. It lives on the value object the aggregate holds, not on the aggregate itself - a different module entirely, one the earlier Step 1 investigation had already named correctly. Items 1-5 are all a STALE conclusion carried forward and asserted as still true; this one is the reverse shape - a CURRENT, already-verified finding effectively forgotten, and a narrower, differently-scoped grep run in its place read as if it were the first and only investigation. Not caught by pytest, ruff, or mypy (a grep of the wrong file for a name that genuinely isn't there doesn't error); caught by the user pointing back to the Step 1 report itself. Same underlying lesson as items 1-5: a fact established earlier in a session is not reliably present later in that same session just because it was already found once - it needs to be re-checked (or at minimum re-grepped broadly, not just in the one file a later question happens to be about) at the point it is needed again, not assumed carried.

### What this phase fixed

The Run #4 reference-case defect from Phase 1: a Full Assessment against an `ip_address` target where 6 of 9 configured scanners never ran, yet the assessment reported `"completed"` with **no coverage-incompleteness disclosure at all** ("Minor issues found — review advised", 88.0/100 "Sound"). Root cause: two independent, drifting scanner-selection mechanisms — `ExecutionPlanner.plan()` (checked only binary/asset availability) and `ScannerOrchestrator.execute_all()`'s own registry-based target-type filtering (silent, no engine notification). A scanner the orchestrator would never dispatch could still be left at `"pending"` in the plan, uncounted by the old "did anything fail" check.

Fixed by making the planner the single source of truth for every scanner's disposition (selected, or one of `SKIPPED_INCOMPATIBLE` / `SKIPPED_BINARY_MISSING` / `SKIPPED_ASSET_MISSING`), seeded immediately — structurally impossible for a scanner that will never run to exist even transiently as "pending". `AssessmentStatus` gained `COMPLETED_WITH_GAPS`, distinct from `COMPLETED`: only every-scanner-succeeded reaches plain `COMPLETED`; any gap (skip, failure, or timeout) reaches `COMPLETED_WITH_GAPS`; zero successes reaches `FAILED`. The report's cover page now carries an unmissable coverage block naming every scanner and its outcome in plain English, and the verdict headline itself is qualified whenever coverage is incomplete — this was the core "invisible failure" the phase exists to close.

Also implemented: `?format=html|pdf` on the report download route (the HTML path was previously dead code — kept and exposed rather than deleted, since it shares the same template generator as the PDF path at zero marginal cost); a startup pass (`ResolveOrphanedAssessments`) that resolves any assessment a prior crash left stuck at `RUNNING` to `FAILED`; and an Alembic migration backfilling the old string-based scanner-status vocabulary to the new enum and adding `reports.assessment_status`.

### A real regression found and fixed during this phase's own gate run

The FIX 3 status-decision block in `submit_assessment.py` was, partway through this phase's own implementation, rewritten in a way that dropped a documented Phase 06 invariant: the block reading `execution_engine`'s per-scanner state was gated only on `execution_engine is not None`, not also on `scanner_executor is not None`. Effect: any assessment run through the plain `scanner.scan()` fallback path (no profile) would have its `scanner_progress` seeded at `PENDING` and never advanced (only the `scanner_executor` path reports lifecycle events back to the engine) — the decision block would then read "0 succeeded" and mark the assessment `FAILED`, even though the scan itself completed successfully with real findings.

Confirmed via direct reproduction against a real wired app + stub scanner: before the fix, a fully successful scan ended `status=failed`; after (restoring the `and scanner_executor is not None` gate), `status=completed`. This also fixed 4 integration tests that had been failing with "assessment did not complete within timeout".

### Also fixed during the gate run (pre-existing, unrelated to the above)

- ~20 test call sites across 8 files still using the old string-based `ScannerRunSummary`/`PlanScannerEntry` status vocabulary (`status="completed"` etc.), broken by the enum migration earlier in this phase.
- Two tests whose assertions encoded a Phase 06/10 assumption ("a skipped scanner doesn't count against coverage") that this phase's own FIX 6 deliberately supersedes — corrected the assertions, not the fix.
- `application/dto.py`'s `ScannerSummaryView.from_domain()` was assigning the raw `ScannerRunState` enum into a `status: str` DTO field instead of `.value` — caught by mypy, fixed at the actual boundary.
- `create_wired_application()`'s new orphan-recovery startup call was running unconditionally, including in test fixtures that create their schema *after* the function returns (`validate_migrations=False`) — caused "no such table" in ~60 integration tests. Fixed by gating the call on `validate_migrations`.

### The web-scan / nmap profile defect

Correction 1's real 5-run timing test (see below) surfaced a genuine, previously-masked defect: the `web-scan` profile (`supported_target_types=(URL,)`) declared `nmap` as a **required** scanner, but nmap's real plugin capabilities (`infrastructure/scanner/plugins/nmap/adapter.py`) never include `URL` — only `IP_ADDRESS`/`HOSTNAME`/`NETWORK`. Under this phase's now-correct compatibility check (target-type checked first, before binary/asset checks), this meant `web-scan` could **never** proceed, for any target — `plan.can_proceed` was unconditionally `False`.

This was not a regression introduced by this phase's logic — it's a real, pre-existing profile-definition bug this phase's own correctness newly exposed. Before this phase, the planner never checked target-type compatibility when deciding "is a required scanner available"; only the orchestrator's own registry filtering did, silently, at dispatch time. So under the old code, `nmap` was marked "selected" at planning time, the assessment proceeded to `RUNNING`, and the orchestrator silently dropped `nmap` from actual execution — the assessment still reported `COMPLETED`. This is corroborated by Phase 1's own evidence: Run #2 (`web-scan`) completed successfully in Phase 1, before this class of check existed.

**Fixed at two levels**, per explicit review:
- **Instance:** `nmap` is now optional in `web-scan` (`required_scanners=()`) but **stays in the profile's scanner list** — removing it entirely would hide a real coverage gap, which is the opposite of this phase's purpose. It is now scheduled, correctly reported as `SKIPPED_INCOMPATIBLE` with the plain-English reason "does not support target type 'url'", and counted honestly toward `COMPLETED_WITH_GAPS`.
- **Class:** added `TestProfileRequiredScannersAreTargetTypeCompatible` (`tests/unit/application/test_phase2a_honest_coverage.py`), a static check across every profile from `ExecutionPlanner.list_profiles()`, using the **real** plugin registry's declared `target_types` (not a stub) — asserts every required scanner is compatible with at least one of its profile's supported target types. Confirmed failing against the pre-fix `web-scan` definition (`AssertionError: profile 'web-scan': required scanner 'nmap' is compatible with none of its supported target types ['url']`) before the fix was applied, and passing after.

**Logged for Phase 2B** (not fixed now): a URL target contains a real host and port. The correct fix is for host-oriented scanners like nmap to derive and scan them, so nmap *can* run against `http://127.0.0.1:18080` instead of being structurally incompatible with every URL. Keeping nmap listed-but-skipped in `web-scan` leaves room for that later.

### Question 1 — the matrix test's registry was a stub, now fixed

The full-matrix planner/orchestrator invariant test (`TestPlannerOrchestratorInvariantAcrossFullMatrix`, 16 real `(profile_id, target_type)` combinations generated from `ExecutionPlanner.list_profiles()` itself) originally used `_PermissiveRegistry`, a fake that reported every scanner compatible with every target type unconditionally. **That stub could never have caught the web-scan/nmap defect above** — a test asserting an invariant against a fabricated registry proves less than it appears to. Rewritten to use the real registry (`register_scanner()` wired with default `Settings()`, the exact function `composition.py` uses in production), and the expected outcome per combination is now *computed from real compatibility data*, not hardcoded: a required-and-incompatible combination must reach `FAILED` at planning time; an optional-and-incompatible one must reach `COMPLETED_WITH_GAPS` naming the gap; only full compatibility reaches `COMPLETED`. All 16 combinations pass against the real registry, post-fix.

### Question 2 — Step 1's Q6 and this phase's Correction 4 both correct; the code changed between them

`PHASE_2A_STEP1_INVESTIGATION.md` Q6 stated the wordlist check "probes hardcoded `/usr/share/wordlists` plus two Linux fallbacks and doesn't even reflect the actual config value." This session's Correction 4 work found the check reading the real configured `FfufSettings.wordlist`/`GobusterSettings.wordlist` path correctly. **Both are accurate — for different points in time.** `git diff` against the pre-session `HEAD` shows the literal old code Step 1 described:

```
-                name="Wordlist directory",
-                path="/usr/share/wordlists",
+                name="Wordlist file",
...
-            Path("/usr/share/wordlists").is_dir()
-            or any(Path(p).is_dir() for p in (
-                str(Path.home() / "wordlists"),
-                "/usr/share/dict",
-                "/usr/share/seclists",
```

Step 1's description was correct for the code as it existed at Step 1's time; Correction 4 (this phase, Step 2) is what removed the hardcoded paths and wired in the real configured value. Not a Step 1 inaccuracy — the code changed between the two reports. Verified live on this Windows host, both directions: a real configured path to a file that exists → `usable=True, missing_assets=()`; unconfigured → `usable=False, missing_assets=('Wordlist file',)` with a `KINGSEC_FFUF__WORDLIST`/`KINGSEC_GOBUSTER__WORDLIST` hint. Step 1's other findings should be weighted as accurate-for-their-time, same as this one — no reason found to doubt them generally.

### Correction 1 — Q7, recorded accurately

Re-ran the 5 repeated `web-scan` runs for real (the earlier result existed only in conversation, never persisted — corrected that here). Against real DVWA, isolated `C:\kingsec-e2e`:

| Run | Elapsed | Status |
|---|---|---|
| 1 | 22.99s | FAILED |
| 2 | 6.78s | FAILED |
| 3 | 6.42s | FAILED |
| 4 | 6.55s | FAILED |
| 5 | 6.36s | FAILED |

5 of 5 distinct values — **Q7 is proven**: elapsed time is genuinely measured per run, not cached or hardcoded (run 1's outlier is cold-start import/connection-pool warmup on the first request).

**Recorded accurately, per explicit instruction:** the original 18.28s/18.28s anomaly (Phase 1, Run #2 vs Run #3) is **CLOSED because the code path that produced it no longer exists**, not because it was reproduced and explained. All 5 of these re-runs failed at planning time (the web-scan/nmap defect above, since fixed) before ZAP or any other scanner was ever invoked — the exact code path that ran ZAP-then-timed-out-near-instantly in Phase 1 was never re-exercised here. Do not read this as "the 18.28s behavior was reproduced and understood" — it was not; the reason it can never recur is that Correction 2a now fails the plan before that code path is reached at all.

### FIX 9 follow-up (logged, not fixed)

`ResolveOrphanedAssessments`'s startup call is gated on `validate_migrations`, using it as a proxy for "the schema is ready to query." These are two different concepts — a deployment that sets `validate_migrations=False` for any other reason would silently skip orphan resolution entirely. Needs its own flag, or a lazy first-request trigger, instead of reusing `validate_migrations`.

### Real DVWA re-verification: Run #4 reproduced and fixed

Re-ran Run #4's exact scenario (`full-assessment` profile, `127.0.0.1` `ip_address` target) against real DVWA, isolated `C:\kingsec-e2e` (migrated to head `64e10236c8c1`), through the real HTTP route layer. Generated the PDF, downloaded it, and inspected its actual rendered content (the same `render_report_html()`/`session.merge()`-persisted `Report` object WeasyPrint converts to PDF — no PDF-rendering tool was available in this environment to rasterize pages directly, so the equivalent HTML was regenerated from the identical persisted `Report` row and inspected instead; the real PDF file itself was also delivered for direct visual review).

**Cover page — old vs. new:**

| | Phase 1 (pre-fix) | Phase 2A (post-fix, this re-run) |
|---|---|---|
| Assessment status | `completed` | `completed_with_gaps` |
| Scanners that ran | 1 of 9 (Nmap) — undisclosed | 1 of 9 (Nmap) — disclosed |
| Coverage statement | **none** | *"Incomplete coverage — only 1 of 9 scanners ran"* |
| Non-running scanners named | **none** (6 silently at `"pending"`, uncounted) | All 8, each with a real reason: Nuclei (missing templates), Gobuster/FFUF/Semgrep/Trivy/Amass/OWASP ZAP/Nikto (target-type incompatible with `ip_address`) |
| Verdict headline | *"Minor issues found — review advised."* | *"Minor issues found — review advised. Coverage was incomplete: 8 of 9 configured scanners did not complete (Nuclei, Gobuster, FFUF, Semgrep, Trivy, Amass, OWASP ZAP, Nikto). This verdict reflects only the scanners that ran — see Scanner Coverage for details."* |
| Score framing | "88.0 / 100 (Sound)" | Same underlying findings (9 Nmap findings, 6 Low/3 Info), but `action_required=True` is now forced by incomplete coverage regardless of severity — an operator can no longer read this as an unqualified clean result |

(Scanner count differs slightly from Phase 1's original 6-of-9-pending — 8 of 9 here, since this environment currently has no Nuclei templates installed, an environment difference, not a regression; the structural fix — naming every non-running scanner with a real reason, on the cover page, unmissable — is what was being verified, and it holds.)

**Correction to `TestReferenceCaseRun4Reproduction` (this phase's own regression test), found via review:** the test originally asserted 3 of 9 scanners succeed (Nmap, Nuclei, Trivy), using a stub registry that incorrectly treated Trivy as compatible with an `ip_address` target. Trivy's real, declared capability (`infrastructure/scanner/plugins/trivy/adapter.py`) is `target_types={HOSTNAME}` only — it can never run against `ip_address` in production, so "3 of 9 succeed" was never a real possible outcome. Phase 1's actual recorded Run #4 (`docs/E2E-EVIDENCE.md`) shows exactly **1 of 9 succeeded (Nmap)**, with Nuclei and Nikto correctly skipped (not succeeded) and 6 stuck pending. Rewrote the test's fixture to use the real plugin registry with discovery statuses matching Phase 1's actual environment (Nuclei installed but missing templates; Nikto not installed) — now correctly asserts 1 of 9 succeeds, 8 of 9 don't, matching both the real Phase 1 evidence and this phase's own live DVWA re-verification above. Full details: `docs/audits/KINGSEC-PHASE-2A-FOLLOWUP-RESPONSE.txt`.

### ACCEPTANCE

- [x] Full gate green: `pytest` exit 0 (entire suite), `ruff check .` clean (full repo), `mypy src` clean (599 files)
- [x] Reference-case regression test reproducing Run #4 exactly, asserting `COMPLETED_WITH_GAPS` — passes against fixed code
- [x] Planner/orchestrator invariant test across every real `(profile, target_type)` combination, against the real plugin registry
- [x] Static class-level validation preventing a future profile from repeating the web-scan/nmap defect
- [x] Migration `64e10236c8c1` applied to `C:\kingsec-e2e` only (confirmed head + schema); `~/.kingsec` confirmed still at `da4b78614806`, untouched
- [x] Real DVWA re-run of Run #4's exact scenario: PDF generated, downloaded, and its actual content inspected — `COMPLETED_WITH_GAPS`, every non-running scanner named with a real reason
- [x] `docs/STATUS.md` updated (this section)

### What's next

Per explicit instruction, **Phase 2B has not been started.** Logged for that phase: the web-scan/nmap URL-host-derivation item above, and the FIX 9 `validate_migrations`-proxy item above.

---

## Phase 2A-b — Coverage-aware verdict, score, and report page 2

**Branch:** `fix/phase-2a-honest-coverage`
**Status:** CLOSED — APPROVED. Full gate green, PDF regenerated from real persisted data, and all acceptance criteria (coverage-aware verdict, PARTIAL COVERAGE band, neutral gauge, score denominator, recommendations count, removal of operator-facing configuration text) verified against the rendered PDF. Phase 2A as a whole is now closed; see the carried-over-conclusion note under Phase 2A above. Phase 2B not started.

### What this phase fixed

Page 1's cover-page coverage callout (Phase 2A FIX 4) was correct and accepted. Page 2 (Executive Summary) still reproduced the Run #4 defect in a different place: a large score gauge, a "SOUND" band label, and "generally sound standing" narrative text for an assessment where only 1 of 9 scanners ran — with the actual coverage caveat appended as a trailing clause on the verdict headline, easy to stop reading before reaching. `Verdict.from_findings()`'s own coverage handling (Phase 2A FIX 6) only ever adjusted `action_required` and appended a caveat; it never touched the score, band, gauge color, or narrative, and never reordered the headline itself.

Fixed, when `assessment_status is COMPLETED_WITH_GAPS`:
1. **Verdict headline now leads with coverage.** `domain/report.py`'s `_coverage_lead()` produces the opening sentence ("Incomplete assessment — N of M scanners ran; findings are partial. ..."); the findings-severity clause is now a subordinate sentence appended after it, never before.
2. **The reassuring band label is suppressed entirely.** `templates.py`'s `_executive_summary()` forces `"Partial Coverage"` (a neutral slate color reused from elsewhere in the module, not a new saturated color) instead of calling `_score_band(score)`, which would otherwise return "Sound"/"Strong"/etc. based on the raw number alone.
3. **The gauge no longer renders in a reassuring color.** `_risk_gauge()` now takes its color as an explicit parameter from the caller instead of deriving it internally from the raw score — the caller (already coverage-aware) supplies the neutral color when coverage is incomplete.
4. **The score string always carries its scanner denominator** when incomplete: `"88.0 / 100 — based on 1 of 9 scanners. Not a posture score."`, replacing the normal narrative text entirely for this case.
5. **The contradiction is gone** — "generally sound standing" and "Action required" can no longer both appear on the same page, since the narrative text itself is now coverage-aware rather than independently derived from the raw score.

Also fixed, same phase:
6. The findings table's "Recommendations" column showed `0` for every finding while the separate Remediation Steps section listed a real recommendation for each of the same findings — the table read `entry.recommendation_count` (raw AI/analyst recommendations only, empty here since no AI provider was configured) while the section below it read `entry.effective_recommendations` (which includes a generic fallback for well-known finding types, e.g. "Open port N"). Fixed the table to read the same effective count the section actually renders.
7. Removed operator-facing setup instructions ("Configure a provider in Settings to include them in future reports") from the AI-unavailable callout — this is a customer-facing deliverable; a customer reading it has no "Settings" to configure. Replaced with a plain factual statement, no instructions.

### A note on trust going forward

This phase's own prompt flagged that my Step 2 report claimed FIX 6 was "already correct from before the context reset; no changes needed" — a claim that turned out to be false (it covered `action_required`/the caveat text, but never the score/band/gauge, and never headline ordering). That is the third instance this engagement of a conclusion carried over from before a context reset being reported as done without being re-verified in the current session (the others: the wordlist check's "no fix needed", and the fabricated 3-of-9 scanner count). Per the new CLAUDE.md rule, any such carried-over conclusion is now treated as unverified until re-checked in the current session, not reported as settled.

### Verified against real, persisted data (not a new scan)

Regenerated the report directly from the real persisted Run #4 assessment in `C:\kingsec-e2e` (`Report.from_assessment()` on the stored `Assessment`, not a re-fetch of the already-generated `Report` row, which would still carry the old pre-fix verdict text baked in at generation time). Confirmed:

- `report.verdict.headline` now starts with `"Incomplete assessment — 1 of 9 scanners ran; findings are partial."`
- Rendered HTML contains no instance of `"SOUND"`, `"Sound"`, `"Strong"`, or `"generally sound standing"`; contains `"Partial Coverage"`.
- Rendered HTML contains `"based on 1 of 9 scanners"` and `"Not a posture score"`.
- Findings table recommendation counts now match the Remediation Steps section (no `<td>0</td>` where a generic fallback recommendation exists).
- AI-unavailable callout no longer tells the reader to "Configure a provider in Settings."
- PDF regenerated: `C:\kingsec-e2e\run4-coverage-report.pdf`.

### LOG FOR LATER — Phase 2B and 2C (not fixed now, per explicit instruction)

- **Phase 2B:** nmap's scanned port range is never disclosed anywhere in the report. It scans roughly the top ~1,000 of 65,535 ports by default, and DVWA's own mapped port (18080 in this environment) is outside that range and was never actually looked at. The Limitations section must state the actual port coverage, not imply a full port scan occurred.
- **Phase 2C:** open-port severity assignment currently appears to follow "recognised service name → Low, unrecognised → Informational." That rates an exposed RDP port (3389) as Low and an exposed SMB port (445) as Informational — the two most-exploited Windows services on the public internet. This is not a real severity model and will not withstand professional review; needs a proper design pass, not a quick patch.

### ACCEPTANCE

- [x] `pytest` exit 0 (full suite), `ruff check .` clean (full repo), `mypy src` clean (599 files)
- [x] Test: a `COMPLETED_WITH_GAPS` report never renders a reassuring band label or a reassuring verdict headline (`TestCoverageAwareVerdictAndScore`, `tests/unit/application/test_phase2a_honest_coverage.py`)
- [x] Test: the score string includes its scanner denominator
- [x] Run #4 PDF regenerated from `C:\kingsec-e2e`'s real persisted data — page 2 no longer says "SOUND" or "generally sound standing"
- [x] Committed separately from the rest of Phase 2A
- [x] `docs/STATUS.md` updated (this section)

### What's next

**Phase 2A is not closed until Abdul has visually reviewed the PDF.** Phase 2B has not been started. Logged for it: the nmap port-range disclosure item and the open-port severity model item above, plus the two carried over from Phase 2A (web-scan/nmap URL-host-derivation, FIX 9 `validate_migrations`-proxy).

---

## Phase 2B — Real coverage

**Branch:** `fix/phase-2a-honest-coverage` (verified via `git branch --show-current` at commit time — a separate `feat/phase-2b-real-coverage` branch does not exist; this phase's work landed on the same branch Phase 2A/2A-b used).
**Status:** Task 1 committed (`13947e5`). This section covers Task 1's decisions only; Task 2 has not started.

### Task 1 — Profile/scanner target-type fit

Full investigation delivered separately: `docs/audits/KINGSEC-PHASE-2B-TASK1-PROFILE-SCANNER-FIT-AUDIT.txt`. This section records the decisions actually applied and their evidence.

**Decision 5 — the static compatibility test's own spec was wrong, fixed first.** `TestProfileRequiredScannersAreTargetTypeCompatible` previously asserted a required scanner need only be compatible with *at least one* of its profile's declared target types — which let `code-review` and `container-scan` both declare `IP_ADDRESS` support while their required scanner (semgrep, trivy respectively) could never run against it. Strengthened to assert every required scanner is compatible with *every* target type its profile declares. Run standalone against the pre-deletion profile set, it failed exactly as expected:

```
AssertionError: profile 'code-review': required scanner 'semgrep' is NOT compatible with ['ip_address'], a target type this profile declares support for
profile 'container-scan': required scanner 'trivy' is NOT compatible with ['ip_address'], a target type this profile declares support for
```

This is the proof the strengthened test now catches the web-scan/nmap defect class generally, not just the one instance already fixed in Phase 2A. Confirmed failing *before* Decisions 1/2 below were applied, per explicit instruction.

**Decision 1 — `code-review` and `container-scan` profiles DELETED, not fixed.** Semgrep and trivy cannot take any target type KingSec's current model expresses (`IP_ADDRESS`/`HOSTNAME`/`NETWORK`/`URL`) — both need a source checkout, image reference, or filesystem path. Both profiles were structurally incoherent from the start. The `semgrep` and `trivy` adapters (and their existing tests) are **kept, not deleted**, with a module-level docstring on each stating they are not wired to any profile and naming what they need.

**Roadmap item (source/supply-chain scanning):** a `repository`, `image`, and `path` target type all need to exist in the domain target model before semgrep or trivy can be wired to anything again. Not scheduled to a phase yet.

**Decision 2 — Amass removed from `external-footprint` and `full-assessment`.** Amass only produces useful results against a real, registrable public domain; `domain/target.py`'s `_validate_hostname()` validates RFC 1034/1123 label syntax only — it accepts `"localhost"` and cannot distinguish a real domain from any syntactically valid hostname-shaped string. Amass also performs active DNS/certificate-transparency lookups against third-party infrastructure with no scope enforcement in the product yet, making it the highest-risk scanner to leave wired under a validation gap. The `amass` adapter and its tests are kept, same docstring treatment as Decision 1.

**Roadmap item (Phase 4 prerequisite for re-enabling amass):** a `registrable_domain` target type with real validation (public suffix check, not RFC 1123 syntax) is a prerequisite for putting amass back into any profile.

**The honest network scanner count is now SIX: nmap, nuclei, nikto, ffuf, gobuster, zap.** `full-assessment` now schedules exactly these six (was nine). Phase 5's claim audit must use six, not nine, as the baseline.

**Decision 3 — nmap stays in `web-scan` (optional, unchanged from Phase 2A); nuclei does NOT get NETWORK added.** Read `infrastructure/scanner/nuclei.py`'s `_build_args()` directly: it passes a single `-u target.value` flag, with no CIDR-expansion or multi-host logic anywhere in the adapter. Nuclei genuinely does not accept a CIDR/NETWORK target as a single invocation. No declaration change made — `network-scan`'s existing nuclei entry (no `NETWORK` in its `target_types`) was already correct; adding it would have reintroduced a declared-but-non-functional capability, the same defect class Decision 5's test now guards against structurally.

**Decision 4 — ffuf and gobuster's `HOSTNAME` declaration was a lie; fixed by dropping `HOSTNAME`, not by deriving a URL.** Both plugins declared `target_types={HOSTNAME, URL}`, but their underlying adapters (`infrastructure/scanner/ffuf.py`, `gobuster.py`) pass `target.value` straight through as the `-u` base URL with no scheme handling — a bare hostname produces an invalid, scheme-less URL at the command-construction layer, not at the declaration layer. Chose **(b): drop `HOSTNAME` from both declarations, URL only** — recommended over (a) deriving `http://<host>` because guessing the scheme is a silent, wrong-by-default assumption for any HTTPS-only target (a redirect, a refused connection, or fuzzing the wrong protocol entirely), and `nikto.py`'s `_parse_target()` proves the codebase already has a correct pattern for genuine dual-mode URL/host handling when an adapter actually implements it — ffuf/gobuster never did. Applied to both plugins' `capabilities()`.

**Third compatibility state — sketch only, not implemented, for Phase 4:**

Today `ScannerCapability.target_types` expresses exactly one binary fact: is this *type* of target structurally acceptable to this scanner at all. It cannot express "acceptable in principle, but only under an additional precondition the target model doesn't capture yet" — which is exactly amass's situation (`HOSTNAME` is structurally fine; a *registrable public domain* is what's actually required) and, on a smaller scale, the general shape of "syntactically valid but semantically useless" inputs.

Proposed shape (not built): add an optional `precondition: TargetPrecondition | None` field to `ScannerCapability`, where `TargetPrecondition` is a small closed set of named, independently-testable predicates (e.g. `REGISTRABLE_DOMAIN`, `ROUTABLE_IP` — non-loopback/non-private — `RESOLVABLE_HOSTNAME`). `ScannerPluginRegistry.is_compatible()` would gain a second, distinct return channel from "no" — something like a three-valued `Compatibility = COMPATIBLE | INCOMPATIBLE_TYPE | INCOMPATIBLE_PRECONDITION` — so the planner can produce a *third* skip reason (`SKIPPED_PRECONDITION_NOT_MET`, alongside the existing `SKIPPED_INCOMPATIBLE`/`SKIPPED_BINARY_MISSING`/`SKIPPED_ASSET_MISSING`) with real user-facing text ("amass requires a registrable public domain; 'localhost' is not one") instead of either silently running uselessly or being unconditionally removed from every profile as this round did. This is the mechanism that would let amass (and, later, semgrep/trivy once `repository`/`image`/`path` exist) come back into a profile honestly instead of needing the type-model itself extended just to express "usually fine, sometimes not."

Not implemented this round — deferred to Phase 4 alongside the `registrable_domain` target type it depends on.

### Gate

```
$ uv run pytest tests/unit/application/test_phase2a_honest_coverage.py -v
27 passed
```

Re-running the full suite surfaced 6 additional stale tests, none of them a new defect — each a direct, mechanical consequence of Decisions 1/2/4 already applied to production code, fixed to match:

- `TestReferenceCaseRun4Reproduction` (2 tests): hardcoded `== 9` scanner counts and an 8-name verdict-headline tuple including Semgrep/Trivy/Amass, stale against `full-assessment`'s new 6-scanner list. Updated to 6/1/5 and the 5 real remaining names; also dropped the now-dead `semgrep`/`trivy`/`amass` entries from the `_STATUSES` discovery fixture.
- `test_ffuf_plugin.py` / `test_gobuster_plugin.py` (4 tests): `TestCapabilities::test_correct_target_types` still asserted `HOSTNAME` was declared, and both files' module-level `_TARGET` fixture (`TargetType.HOSTNAME`) broke every provisioning/orchestrator-resolution test the moment the plugins stopped declaring it. Moved `_TARGET` to a real `TargetType.URL` value and one exact-match gobuster assertion (`test_build_args_includes_target`) from `"example.com"` to `"http://example.com"`.

Final, full-repo gate, all green:

```
$ uv run pytest -q
exit code: 0, 0 FAILED entries, all collected tests passed
```

```
$ uv run ruff check .
All checks passed!
```

```
$ uv run mypy src
Success: no issues found in 599 source files
```

### What's next

Task 1 approved. Task 2 (URL target model) is IN PROGRESS — see the section below. Full write-up: `docs/audits/KINGSEC-PHASE-2B-TASK2-STEP2-C1-C2-REPORT.txt`.

---

## Phase 2B Task 2 — URL target model (Step 2, in progress)

**Status:** Decisions 1, 2, 4 and Additions 1, 2 implemented and gate-green. Decision 3 (moving URL validation into `Target._validate_format()`) is DESIGNED but NOT APPLIED — gated behind C1 (persisted-data check, done) and C2 (graceful-load-failure design, proposed) per explicit instruction to stop there for approval. Not committed yet.

Capability-based compatibility is live: `ScannerRequirement` (`REACHABLE_HOST`/`HTTP_BASE_URL`/`NETWORK_RANGE`) replaced `ScannerCapability.target_types`; `is_compatible()` keeps its exact signature. `UrlComponents`/`decompose_url()` (domain/target.py) do the actual URL decomposition, computed on demand, never persisted. nmap now runs against `URL` targets (the Task 2 goal) and against an IP_ADDRESS/NETWORK IPv6 literal (Addition 1's pre-existing bug, found and fixed alongside it — without `-6`, nmap silently skips an IPv6 target as "invalid" rather than erroring, verified against a real nmap 7.99 binary). nikto's compatibility also expanded to `IP_ADDRESS` (Decision 1, approved) — its own `_parse_target()` already handled a bare IP correctly, this only recognizes it.

Decision 4's nmap port scope required empirically testing real nmap CLI behavior (`-p` combined with `--top-ports` on the same command line does not reliably resolve to "the last flag wins" — verified three different orderings, got three different winners depending on port-list content, not position). The fix: never combine the two flags at all — a URL-derived scan always gets exactly one `-p <explicit-port>,<host_port_range>` list, and any operator-configured `-p`/`--top-ports`/`-p-`/`-F` in `scan_args` is stripped out first (with a warning logged naming what was overridden) rather than left to an unreliable flag-precedence race. The exact resolved spec is recorded on `ScannerResult.port_specification` via the same pure function `_build_args()` itself calls, so the recorded and scanned specs cannot drift apart.

**CORRECTION, same round:** the default range as first implemented (`"1-1000"`, a literal contiguous numeric range) was a coverage regression, not a fix — flagged and confirmed before being shipped further. Checked against Phase 1 Run #4's nine real found ports (135, 445, 902, 912, 1001, 3000, 3389, 5357, 5678): five of nine (1001, 3000, 3389 — RDP, 5357, 5678) fall outside `1-1000` and would have been missed. Verified nmap's REAL frequency-ranked `--top-ports 1000` (extracted from this machine's own `nmap-services` file, not the literal range that was actually implemented) DOES include all nine (ranks 7–812) — the mistake was implementing a numeric range instead of nmap's actual ranking. Proposed fix (not yet applied): freeze a snapshot of nmap's real top-1000-by-frequency list as KingSec's own explicit, documented, version-controlled constant (not a runtime read of nmap's own data file, which is fragile across installs/versions), unioned with the URL's explicit port. Full write-up: `docs/audits/KINGSEC-PHASE-2B-TASK2-DECISION4-CORRECTION-AND-CONDITIONS.txt`.

### Recurring defect class: "nothing found" vs. "nothing looked"

Named pattern, logged for future phases to hunt for actively rather than rediscover by accident. Three confirmed instances so far, all this engagement:
1. Pre-Phase-2A: scanners silently stuck `PENDING` forever read identically to "nothing to report" (the original Run #4 defect).
2. Pre-Phase-2A-b: an 88/100 "Sound" verdict on 1-of-9 real coverage read identically to a genuinely clean, fully-scanned result.
3. Phase 2B Task 2: nmap silently skipping an IPv6 target as "invalid" produces zero findings, exit success — identical to a real clean scan of a real reachable host (Addition 1).

A fourth is what Conditions 1/2 (see the Decision 4 correction report above) exist to close before it ships: a corrupted assessment row silently dropped from a list, or from startup orphan-recovery, would read identically to "that row doesn't exist" or "nothing was orphaned."

**A fifth instance was introduced and caught inside the very phase that named this pattern.** Task 4's first cut of the port-coverage disclosure (this file's own port-coverage-disclosure section above) made `ScannerRunSummary.port_specification=None` mean three different things at once, all rendering as the SAME sentence: (a) a genuine non-URL run where nmap used its own unmodified default — the one case that sentence was actually true for; (b) a row persisted before this field existed at all — genuinely unknown; (c) a URL-target row from before the two-invocation design ran — also genuinely unknown. The regenerated Run #4 PDF rendered case (b) as case (a) and happened to be true, which was luck, not design — Run #4's real target genuinely is non-URL, so the wrong-reason sentence was accidentally the right sentence. Fixed: a genuine non-URL run now RECORDS an explicit sentinel string (`NON_URL_DEFAULT_PORT_SPECIFICATION`, nmap.py) instead of leaving the field absent — `None` now means exactly one thing, "not recorded," and renders as an honest "port coverage for this scan was not recorded; treat the port scope as unknown" instead of guessing. Required test (`TestPortCoverageDisclosure.test_absent_key_and_explicit_non_url_sentinel_render_different_disclosures`, test_templates.py): an absent-key summary and an explicit-sentinel summary must render different disclosures — the fix is only real if they do.

**Instance six inverts the pattern — a FAILURE rendered as a SUCCESS.** Task 5 (ZAP-on-Windows): `ScannerDiscoveryService._get_version()`'s regex (`[\d.]+`) matched the bare period in ZAP's real chocolatey-shim failure text, "The input line is too long." — a total invocation failure (raw `CreateProcess` cannot execute a `.bat`) produced a plausible-looking version string ("v.") instead of no version at all. Every prior instance in this list is an *absence* silently reading as *clean* ("nothing found" reading as "nothing to report"); this one is the opposite shape — an outright, non-zero-exit *failure* silently reading as a *working* scanner, the most dangerous variant found so far because it doesn't even need an attacker or a missing feature, just any error text containing a period, for any of the 9 scanners' regexes (all shared the same unbounded `[\d.]+` pattern). Fixed: `version_regex` tightened to `\d+(?:\.\d+)*` (at least one digit) across all 9 manifest entries, and the new `_probe_version()` (replacing `_get_version()`) gates extraction on `returncode == 0` — a failed invocation never even reaches the regex, regardless of what its output contains. Required tests (`TestVersionProbeNeverParsesAFailureAsSuccess`, `test_scanner_discovery.py`): stderr containing "The input line is too long." yields no version, and a non-zero exit never yields a version even when the output looks like a real, parseable version string. Closes the "Backlog — ZAP version string parses as 'v.' on Windows" item below.

**Instance eight is the most consequential form of the pattern found so far: a silent zero-findings success across the product's entire history.** Task 5B (ZAP hang investigation, follow-up): `ZapScannerAdapter.scan()` called `parse_zap_json(result.stdout)`, but ZAP writes its real JSON report to the FILE named by `-quickout` — stdout only ever carries a "Writing results to <path>" line and progress/log text, confirmed empirically against the real binary (both for the bug and for the fix). Every real ZAP scan this product has ever run, in any environment, returned zero findings while logging "zap scan completed" — a clean, successful-looking log line for a scan that never actually examined its own output. Reproduced directly against a live target: the real ZAP binary genuinely found four alerts (CSP, anti-clickjacking, server-version leak, X-Content-Type-Options) that were silently discarded by the old code path. `returncode` was equally untrustworthy on its own — verified empirically that ZAP's `-cmd` mode can exit 0 while reporting a real configuration error ("the directory ... is not writable") with no output file written at all. Fixed: `ZapScannerAdapter._read_findings()` now reads the `-quickout` file directly and requires three things before treating a scan as successful — the file exists, is non-empty, and parses as ZAP-shaped JSON (a dict with a `"site"` key) — with a distinct, named reason for whichever check fails; a genuinely clean scan (valid report, zero alerts) remains a legitimate success, never conflated with "never produced a report at all." The output file is deleted after every scan (success or failure) so it does not accumulate in the data directory. Required tests (`TestFileBasedSuccessCheck`, `test_zap_plugin.py`): exit 0 with no output file is FAILED, not a zero-findings success; a real ZAP JSON file parses into findings; empty file, malformed JSON, and a valid-but-wrong-shaped JSON file are each FAILED with a distinct reason; a genuinely empty `{"site": []}` report is a legitimate success.

**Phase 5 BLOCKER — scanner licensing risk, investigated and documented:** `docs/LICENSING-RISK.md` (new, this round) reviews all six wired scanners' own license text (nmap NPSL, nuclei MIT, nikto GPLv3 + proprietary DB files, ffuf MIT, gobuster Apache-2.0, ZAP Apache-2.0) against how KingSec actually uses each one (arm's-length external subprocess invocation only — no scanner binary or data file is ever bundled, vendored, or shipped; every `binary_path` defaults to a bare PATH-resolved command name, confirmed by reading `infrastructure/config/models.py` and the `Dockerfile`). Verdict: CLEAR for all six today, with two flagged conditions — nmap and nikto's clearance depends on KingSec never bundling their binaries/data files into a future installer or Docker image, and nikto's clearance additionally rests on the standard (not codified-in-law) GPL subprocess-invocation interpretation. Rank this above the wordlist/Nuclei-template licensing items already logged elsewhere in this file — those are lower-risk instances of the same underlying question this document settles more thoroughly.

**Addition 2 — Phase 5 claim-audit item, data handling:** a URL containing embedded credentials is logged verbatim at INFO by all six wired scanner adapters' `_logger.info(..., target=target.value, ...)` calls (nmap, nuclei, nikto, ffuf, gobuster, zap — confirmed by reading each) and persisted to the `assessments.target_value` column as plain, unencrypted text. Decision 3 (once applied) closes the *input* path — a credentialed URL will be rejected at `Target` construction and can never reach a scan or a log line — but the claim audit still needs to state plainly what the product does and does not protect: target values are not encrypted at rest, and were not redacted in logs before this fix. Log this alongside the existing "local-first" class of product claims.

**Phase 2B-c claim-audit item, HIGH PRIORITY — KingSec has no concept of authentication.** Task 6's real E2E run against DVWA and Juice Shop (`docs/E2E-EVIDENCE-PHASE2B.md`) proved this directly, not by inference: five real assessments, zero findings resembling either application's actual headline vulnerabilities (SQLi, XSS, broken auth, insecure deserialization — all post-login or authenticated-API surface). KingSec performs unauthenticated, external assessment only. An SME buyer hearing "security assessment" will reasonably assume their application's business logic is in scope; it is not, today. This needs to be a stated boundary in any customer-facing claim, not an implicit one discovered later. **Roadmap capability, same audit:** credentialed/authenticated scanning (accepting a login flow or session token as target configuration so scanners can operate past a login page) is not built and not scheduled.

### C1 — persisted data check (read-only, both databases)

```
C:\kingsec-e2e\kingsec.db      : 10 rows with target_type='URL', all identical value
                                  "http://127.0.0.1:18080" (the Phase 1/2A DVWA
                                  target, reused across runs)
~/.kingsec\kingsec.db          : 0 rows with target_type='URL' (1 row total, IP_ADDRESS)
```

Queried via Python's `sqlite3` module opened `file:...?mode=ro` (read-only URI — never plain `sqlite3.connect(path)`, which can create `-wal`/`-shm` files as a side effect of opening even for a read). First pass used `target_type = 'url'` and found nothing — caught before reporting: `mappers.py` stores the enum's `.name` ("URL"), not `.value` ("url"); re-queried with the correct casing and cross-checked against the real total row count and full `target_type` distribution before trusting the result.

Ran the actual `decompose_url()` (not a re-implementation) against the one distinct persisted value: **accepted cleanly** — `http://127.0.0.1:18080` has no credentials, a valid in-range numeric port, no IPv6 ambiguity. **No existing row in either database would fail the new validation.**

### C2 — graceful handling for a persisted row that fails validation (proposed, not implemented)

Traced every caller of `assessment_to_domain()` (`mappers.py`): `get()`/`load_assessment()` (single-fetch by id, 2 call sites) and **6 separate list-building call sites** across `repositories/assessment.py` and `_operations.py` (`list()`, `find_by_schedule_occurrence_id()`, `find_running()` — the last one backs the **startup** orphan-recovery pass, `ResolveOrphanedAssessments`, not just an HTTP endpoint). All 6 list sites use a bare `[assessment_to_domain(o) for o in orms]` — one bad row raises and the entire list call fails, confirming the exact risk flagged: a validation tightening could turn one corrupted row into a failure for every unrelated request that lists assessments, or worse, a failure at process startup.

**Proposed fix (not applied):**
- The 6 list-building call sites: wrap each row's `assessment_to_domain(o)` in a per-row try/except catching `InvariantViolation`/`TargetDecompositionError`, log the assessment `id` only (never `target_value` — that is exactly the class of value Decision 3 exists to stop leaking, so it must not leak through this path instead), and skip that row — the rest of the list loads normally. `find_running_assessments()` specifically logs at ERROR (not WARNING): a RUNNING row the orphan-recovery pass can't even evaluate needs operator visibility, not a quiet skip.
- The 2 single-fetch call sites (`get()`/`load_assessment()`): do NOT skip silently — the caller asked for that specific row. Propose translating the validation error into a new, narrowly-scoped `AssessmentDataCorruptedError` (application/errors.py, sibling to `AssessmentNotFoundError` — not reusing it, since "not found" and "found but unloadable" are different facts an operator needs to distinguish), mapped at the HTTP boundary to a clear, honest error response instead of a raw traceback.
- Noted, not fixed here: `repositories/assessment.py`'s `list()`/`find_running()`/`find_by_schedule_occurrence_id()` and `_operations.py`'s `list_assessments()`/`find_running_assessments()`/`find_assessments_by_schedule_occurrence_id()` are two independent implementations of the same three queries (one SQLAlchemy 2.x `select()`-style, one older `session.query()`-style) — both need this fix since they don't share code today. Worth its own consolidation pass eventually; out of scope for this fix.

Touches 4 files: `mappers.py`, `_operations.py`, `repositories/assessment.py`, `application/errors.py`. Not yet implemented — stopping here per instruction, for approval before applying Decision 3's actual `Target._validate_format()` change.

### Decision 4, SECOND correction — the 61-port list itself was still a regression; superseded by a two-invocation design

The "Proposed fix" above (freeze nmap's real top-1000-by-frequency list as a KingSec-owned constant) was implemented, then rejected on **licensing** grounds: nmap's frequency data (`nmap-services`) is Nmap Public Source Licensed, incompatible with committing it into KingSec's own commercially-licensed source tree. Rebuilt from scratch as `nmap_default_ports.py` — 61 ports sourced only from public IANA documentation plus Phase 1's own evidence, applied unconditionally via `-p` to every nmap invocation (including non-URL targets).

That 61-port list was then flagged as **still** a coverage regression (1000 real default ports narrowed to 61, applied even where no URL/port question exists at all). Resolved by replacing the single-invocation `-p <61-port list>` design entirely:
- **Non-URL targets** (`IP_ADDRESS`/`HOSTNAME`/`NETWORK`): single invocation, no port flag at all — byte-identical to before this whole feature existed. Regression-tested (`TestNonUrlTargetsNeverGetAPortFlag`, `test_nmap_plugin.py`): fails if a port flag is ever reintroduced for these target types.
- **URL targets**: two invocations — (a) a host sweep with no port flag (nmap reads its own real default port data itself; KingSec never touches, copies, or redistributes it), (b) the URL's explicit port alone (`-p <port>`, verified against a real nmap 7.99 binary to be the one case where `-p` reliably wins over any operator-configured `--top-ports`/range). Results are merged and deduplicated by `(port, protocol)` (`_dedupe_findings()`, `nmap.py`).
- **Failure semantics** (`_scan_url_two_invocations()`): both invocations succeed → clean success, no warning. Both fail → `ScannerExecutionError`, scan reaches FAILED. Exactly one fails → SUCCEEDED with a warning naming which sweep failed, via `ScannerRunSummary.warnings` — a silent partial result was explicitly rejected as unacceptable.
- `nmap_default_ports.py`'s 61-port list is kept, committed, and documented, but its docstring now states plainly that nothing in the live scan path references it — it is a documented floor, not a default, for a future scenario (nmap's own default data unavailable/disabled) where a licensing-clean KingSec-owned override is needed.

### Backlog — 4 duck-typed `AssessmentRepository` fakes (logged, not fixed)

A 5th duck-typed fake (`_FakeAssessmentRepository` in `test_phase2a_honest_coverage.py`) was found breaking after `ResolveOrphanedAssessments` was rewired onto the new `find_running_ids()`/`force_fail_running()` abstract methods, and was fixed this round (now formally inherits `AssessmentRepository`). The following 4 are the **same defect class** — a plain `class FakeAssessmentRepository:` with no base class, so a signature change to the real `AssessmentRepository` port would fail silently (an `AttributeError` at call time, not an interface-conformance error at definition time) instead of loudly. **Not fixed — logged as a backlog item only, per explicit instruction; each is its own change with its own blast radius:**

1. `tests/unit/application/test_submit_assessment.py`
2. `tests/unit/application/test_submit_assessment_execution_ledger.py`
3. `tests/unit/application/test_submit_scheduled_assessment.py`
4. `tests/unit/infrastructure/test_schedule_finalization_race.py`

### Backlog — ZAP version string parses as "v." on Windows (RESOLVED, Task 5)

`kingsec doctor`, run for real on this Windows host (Task 3), showed
`[OK       ] zap       (OWASP ZAP) v.` — `ScannerDiscoveryService`'s
version-extraction regex (`([\d.]+)`) matched the bare period in ZAP's
real chocolatey-shim failure text rather than a genuine version. At the
time this was logged as cosmetic-only ("`usable` is unaffected"); Task 5's
full diagnosis found that framing was itself wrong — the underlying
invocation was a total failure, not a cosmetic parsing quirk, and
`usable` being unaffected was the actual bug (see recurring-defect-class
instance six, above). Both are now fixed: the regex requires a digit,
extraction is gated on a zero exit code, and a located-but-unexecutable
binary is reported NOT usable with a reason naming the execution
failure — never `[OK]`.

### Backlog — profile duration estimates are wildly optimistic (logged, not fixed, Phase 2B-c)

Task 6's five real runs (`docs/E2E-EVIDENCE-PHASE2B.md` §2) each finished
far under their profile's stated estimate — a `web-scan` profile quoted
"60 min" and finished in 391s (6.5 min), an `api-scan` quoted "45 min"
and finished in 369s (6.15 min), `full-assessment` quoted "60 min" and
finished in 169s (2.8 min). Every profile overshot its own estimate by
roughly 8-20x, consistently, not as an outlier on one run. Wherever this
estimate is shown to an operator before they start a scan (profile
selection UI, API response), it materially misrepresents how long the
scan will actually take. Not investigated further and not fixed here,
per instruction — recorded as found. Whoever picks this up next should
start by finding where the estimate is computed and check whether it is
a hardcoded per-profile constant rather than derived from anything real.

### Backlog — asset-attribution defect (reframed from "HOST SERVICES contamination", GAP-1 fix round, logged, not fixed)

**Reframed.** This was originally logged as "HOST SERVICES contamination" —
framed as if nmap scanning beyond the assessment's own port were the
problem. It is not: nmap's host-sweep scans the whole host, not just the
target's own port, and on a real engagement against e.g. `https://client.com/app`,
that host's *other* ports genuinely belong to that client — the scanning
itself is correct and valuable coverage, not noise to be filtered out.

The real defect is **attribution**. Every finding nmap produces —
whether it's the target's own port or another port on the same host — is
currently attributed to `assessment.target` (the URL/hostname string),
not to the host:port it was actually observed on. Confirmed directly
against real evidence this round
(`Downloads\KINGSEC-CLEAN-TARGET-REAL-SCAN-attempt.pdf`): a finding
titled "Open port 3389/tcp" (RDP — a host-level service, nothing to do
with the assessed application) rendered with **Affected Asset:
`http://127.0.0.1:18090 (url)`** — the nginx container's own URL. A
client reading "affected asset: your web app URL" next to a database or
RDP port finding will not trust the report, regardless of how accurate
the underlying port scan was.

**The fix, when scoped:** every finding must be attributed to the asset
it was actually observed on — host:port for nmap findings, the URL for
web-layer scanners (ffuf, gobuster, ZAP, nuclei-on-http, etc.) — never to
the assessment's target string as a blanket label. This:
  - resolves the original "host services contamination" complaint as a
    side effect (the host's other-port findings become honestly
    attributed to the host, not falsely pinned to the target URL, so
    they stop reading as contamination of the target's own findings);
  - resolves the localhost-absurdity case (`127.0.0.1:<port>` picking up
    this machine's own unrelated background services — RPC, SMB, VMware
    ports, RDP, WSDAPI, plus this host's own `vantriqsec-crm`/
    `vantriqsec-n8n` services, both confirmed pre-existing, off-limits,
    read-only, never touched) as the same case of the general defect,
    not a special one;
  - is a **prerequisite for multi-host assessments** — any future feature
    that assesses more than one host per assessment cannot honestly
    report per-host findings until attribution is per-finding instead of
    per-assessment.

Full original detail in `docs/E2E-EVIDENCE-PHASE2B.md` §4 ("Host
services vs. target findings") — still accurate as a description of the
symptom, superseded by this entry as the diagnosis of the cause.

**Not fixed.** This touches the finding model itself (adding a real
observed-asset field, distinct from the assessment's target) — its own
scoped piece of work, not attempted in this round. Any severity/count
aggregation across runs — a dashboard, a trend chart, a cross-assessment
rollup — remains at risk of double-counting the same unrelated services
in every run's totals until this is fixed; that risk from the original
entry still stands.

### Status — the no-signal score override (`_is_no_signal`/`_NO_SIGNAL_COLOR`/`_NO_SIGNAL_LABEL`, `infrastructure/reporting/templates.py`): TESTED, NOT RENDERED

Phase 2C Step 2's no-signal override — the band/label substitution applied
when a report's `severity_counts` carries nothing above Informational
(including the zero-findings case) — is unit tested and that coverage is
trusted. It has **never been rendered from real scan data** on this
machine, and cannot be, until the asset-attribution defect immediately
above is fixed.

Two honest attempts were made this engagement to produce a real,
genuinely clean rendering as evidence:
  1. GAP-1's own re-render (a real assessment with zero scanner coverage)
     — correctly refused by `derive_assessment_status()` (a FAILED
     assessment must never produce a scored report at all), so it never
     reached the no-signal override in the first place.
  2. A real Docker/nginx target stood up specifically to produce a
     genuinely clean, fully-covered result
     (`Downloads\KINGSEC-CLEAN-TARGET-REAL-SCAN-attempt.pdf`) — blocked
     by the asset-attribution defect above: nmap's host-sweep findings
     (this machine's own unrelated services, e.g. RDP on 3389) got
     attributed to the target URL, so the result was never actually
     clean/no-signal, regardless of the target's own findings.

Both attempts were blocked by the same root cause, not by the override
itself. No third attempt was made — per instruction, an honest "tested,
not rendered, here is why" stands as the record for this item until
asset attribution is fixed.

### Backlog — `max_concurrent_assessments` silently does nothing (logged, not fixed, GAP-1 fix round)

`settings.performance.max_concurrent_assessments`
(`infrastructure/config/models.py:657`) has no live integration point
anywhere in the running application right now. KSEC-87-02 already built
the real enforcement mechanism honestly — `AssessmentConcurrencyPort`
(`application/ports/outbound/assessment_concurrency.py`), an atomic
`try_reserve_slot()`/`release_slot()` implementation
(`infrastructure/persistence/repositories/assessment_concurrency.py`), a
dedicated `assessment_concurrency_slots` table (migration
`2026_09_03_000000__add_assessment_concurrency_slots.py`), and
`TooManyConcurrentAssessmentsError` — but the only place that ever called
`try_reserve_slot()` was the now-deleted `StartAssessment` use case's own
DI wiring in `bootstrap/composition.py`. `submit_assessment.py` (the one
real orchestrator every live submission path uses today) never called it
at all, and `AssessmentConcurrencyPort` is not even DI-registered in
`bootstrap/composition.py` anymore. Confirmed via a repo-wide grep for
`try_reserve_slot(`: zero call sites outside the port definition, its own
adapter implementation, and `tests/unit/infrastructure/test_assessment_concurrency.py`
(which exercises the mechanism directly, not through any use case). The
setting can be changed via `KINGSEC_PERFORMANCE__MAX_CONCURRENT_ASSESSMENTS`
and nothing in the running application will ever read it.

**Claim-audit flag for Phase 5:** `docs/ADMIN_GUIDE.md` currently tells
admins this is a real, functioning control — twice: "Increase max
concurrent assessments for larger teams" (Performance Tuning) and
"Reduce max concurrent assessments in System Settings" (Troubleshooting
→ Performance Issues During Assessments), the latter additionally implying
a "System Settings" UI exists to change it. Neither claim is true today —
the setting is fully inert. Not corrected in this round (out of scope);
flagged here specifically because it's exactly the misrepresentation risk
Phase 5 exists to catch (`docs/REMEDIATION-PLAN.md`'s Phase 5 "Truth
pass").

**Fix, when scoped:** either wire `try_reserve_slot()`/`release_slot()`
into `SubmitAssessment.execute()` (claim before `job_runner.submit()`,
release in the background job's terminal paths) so the setting does what
`ADMIN_GUIDE.md` already claims, or remove the setting from `Settings`
and correct `ADMIN_GUIDE.md` to stop describing a control that doesn't
exist. Either resolution is acceptable; leaving it half-built (a real,
tested enforcement mechanism sitting completely disconnected from the one
production code path that would use it) is not.

### Backlog — scan-time AI enrichment has the same per-finding spam defect Priority 2 fixed elsewhere (logged, not fixed)

Discovered live during Phase 2B-c's Runs 1-3 re-run
(`docs/E2E-EVIDENCE-PHASE2B.md` §3b): Priority 2's 5a fail-fast fix was
scoped to `generate_report.py`'s `_with_ai_explanations()` (the report-
render freeze, Defect 5's original evidence). A **separate** call site,
scan-time enrichment in `submit_assessment.py` (already noted in that
method's own docstring as mirroring the same best-effort pattern), was
never touched and still calls the AI port once per finding with no
up-front `is_configured()` check. Confirmed directly against the real
re-run: 56 "AI enrichment failed (best-effort): [KS-EXT-001] no AI API
key configured" log lines across three scans against an environment with
no AI provider configured, proportional to finding count exactly the way
Defect 5's 14,043 lines were. Same defect class, same fix shape (5a's
`is_configured()` check, applied once before the loop instead of caught
per-finding) would apply here too. Not fixed — out of scope for this
round, logged per the same "log, don't fix" instruction as the other two
items above.

### Backlog — Limitations section is a wall of text, defeating its own disclosures (logged, not fixed, Phase 2C Step 2, TOP ITEM for a future report-design phase)

Real PDF evidence (Phase 2C Step 2's GAP report): the Limitations section
is now ONE PARAGRAPH containing seven distinct, independently-derived
disclosures — point-in-time scope, false positive/negative risk, CVE
correlation, port coverage (Task 4), rate limiting (Phase 2B-c Priority
3), authentication scope (Phase 2C Step 2 Addition 1), and config-change
invalidation. Every one is honest and individually hard-won — each was
its own investigation, its own fix, its own test. On a real rendered
report this lands as an unbroken block of prose at the end of page 31.

**This is no longer cosmetic.** The disclosure mechanism this whole
phase (and Phase 2B-c, and Task 4 before it) spent weeks building —
"derive the real gap, never hardcode a claim, state it plainly" — has
been defeated by formatting, not by content. A disclosure an SME will
not read past the first two sentences of is not functioning as a
disclosure, regardless of how accurate its text is.

**Not fixed here** — this needs its own scoped pass (structured
subheadings or a bulleted list per disclosure, not one prose paragraph;
possibly grouped by theme — scope/coverage vs. methodology/confidence),
with its own review of how it reads on an actual printed page, not
squeezed into a fix round already covering five unrelated defects. Log
this as the **first item** whenever a report-design phase is scoped —
every disclosure mechanism built in Phase 2C (and Task 4, and Phase
2B-c) feeds into this same paragraph, so fixing its presentation is a
prerequisite for any of those disclosures actually being read, not an
independent nicety.

---

## Phase 3 — Auth hardening

**Branch:** `fix/phase-3-auth-hardening` (based on `feat/phase-2c-scoring-v2`)
**Status:** Implementation complete, gate pending. Scope: registration,
first-admin bootstrap, the lockout duplication (see the carried-over-
conclusion pattern's fifth instance, above, and the resolved Backlog
item #2), related config and tests.

### The defect

Self-registration was enabled by default with no way to disable it, and
`RegisterUser` atomically granted ADMIN to whichever caller's insert was
first to observe an empty `users` table (KSEC-73-05). On any network-
reachable instance, the first unauthenticated caller to reach
`/auth/register` — the only one of the four public, unauthenticated
routes with no rate limit — permanently owned the system. Full
investigation: `POST /auth/register` had no auth dependency, no rate
limit, and no gate of any kind; the shipped `docker-compose.yml` already
sets `KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true` inside the container, so
the only thing standing between a default deployment and exposure was
the host-side port mapping (`127.0.0.1:8765:8765`) — a one-line operator
edit away, not a rare, deliberate opt-in.

### What changed

- **Self-registration is OFF by default** (`SecuritySettings.
  allow_self_registration = False`, `KINGSEC_SECURITY__ALLOW_SELF_
  REGISTRATION` to override). `RegisterUser.execute()` refuses before any
  other check, with a message naming exactly what to do: "run kingsec-
  bootstrap" when no admin exists yet, or the env var name when one
  already does and registration is just turned off.
- **Self-registration can never grant ADMIN again, regardless of this
  flag.** The atomic `CASE WHEN COUNT(*)=0 THEN 'ADMIN'` bootstrap-claim
  SQL is gone. `UserRepository.save_new_user_claiming_bootstrap_admin`
  is now `save_new_user` — a plain insert, role exactly as given, first
  user or not. This is the part that actually closes the vulnerability;
  the flag alone would only have moved the race to whenever an operator
  re-enables registration.
- **`kingsec-bootstrap` is now the ONLY way an initial admin gets
  created.** Its existing guard (refuses if an admin already exists) is
  **kept as-is, deliberately** — a stricter "refuses if any user exists"
  guard was considered and explicitly rejected: this tool's stated
  purpose is recovery after admin loss, and the stricter guard would
  refuse in exactly that scenario if ordinary user accounts survive. The
  weaker guard defends against what it needs to (a second admin behind
  an existing admin's back); nothing in this phase's design depends on
  it being stricter, since the grant-logic removal above is what closes
  the actual race.
- **The bootstrap password is now validated** — previously zero
  validation on the path that creates the most powerful account in the
  system, while self-registration had full validation. Reuses
  `ChangePassword._validate_password`, the same canonical policy
  `admin_users.py` already reuses for the identical reason.
- **`GET /health` gains `bootstrap_required: bool`** (`count_by_role
  (ADMIN) == 0`) — the one public, unauthenticated signal that an
  operator must run `kingsec-bootstrap`, without needing to read source
  or provoke `/auth/register`'s 403 just to find out.
- **Both Q6 audit gaps closed.** New `AuditAction.ADMIN_BOOTSTRAPPED`,
  distinct from `USER_REGISTERED` — an operator scanning for admin-
  creation events now finds a self-describing entry instead of having to
  filter by role. `kingsec-bootstrap` now records one (best-effort,
  matching the existing `_publish_audit` pattern), closing the one
  admin-creation path that previously had zero audit trail at all.

### A real, pre-existing bug found while testing kingsec-bootstrap (not fixed, flagged here)

`_bootstrap.py` had **zero test coverage before this phase.** Writing
its first tests (which necessarily call it more than once, to test the
admin-exists guard) surfaced a genuine, reproducible defect, confirmed
via two independent, real `python -m kingsec._bootstrap` subprocess
invocations — not a test-harness artifact: **running `kingsec-bootstrap`
a second time against an already-bootstrapped instance prints the wrong
error.** Instead of "an admin user already exists," it prints "ERROR:
migrations not applied; run 'kingsec-migrate' first" — actively
misleading advice, since migrations genuinely are applied. Root cause:
`_migrations_applied()`'s `alembic check` subprocess reports several
unrelated backup/scan-snapshot tables (`scan_snapshot`,
`backup_verification`, `backup_schedule`, `backup_recovery_test`,
`scan_restore`, `backup_recovery_plan`, `scan_backup`) as "removed" —
i.e. present in the database but no longer defined in the live ORM
metadata — but only on the **second** `alembic check` invocation in a
process's lifetime, not the first. Not root-caused further (a deep,
pre-existing `alembic`/model-registration interaction, unrelated to
registration/bootstrap/lockout) and not fixed here — out of this
phase's scope. `tests/integration/test_bootstrap_cli.py`'s admin-exists
test isolates around it (patches `_migrations_applied` for the second
call specifically, with a comment explaining why) rather than either
hiding it or blocking on it. **Whoever picks this up:** this makes
`kingsec-bootstrap` unsafe to run twice in a row today, which is an
entirely ordinary thing for an operator to do (confirming a typo,
re-running after an unclear result) — worth prioritizing.

### Tests

`tests/integration/test_bootstrap_cli.py` (new — first coverage this CLI
has ever had): creates an admin and asserts a findable `ADMIN_BOOTSTRAPPED`
audit entry distinct from `USER_REGISTERED`; refuses when an admin
already exists; rejects a weak password before touching the database.
`tests/unit/application/test_register_user.py`: registering with self-
registration disabled grants nothing, with the two distinct messages
(no admin yet vs. admin exists); every self-registered user is Viewer,
first or not (replacing the old admin-grant assertions, which tested the
exact vulnerability). `tests/unit/adapters/inbound/web/test_routes.py`:
`/health`'s `bootstrap_required` in both states.
`tests/unit/application/test_rate_limit_use_cases.py`:
`test_live_lockout_duration_is_fixed_not_progressive`, pinning current
behavior per the carried-over-conclusion pattern's fifth instance above
— replace, don't delete, if escalation is ever implemented.

### Backlog — progressive lockout escalation is not implemented on the live path (logged, not fixed, Phase 3, explicit decision)

Overruling the phase's own Step 2 starting position: escalation needs a
new persisted field, a migration, a tiering policy, and a decay rule —
none of that is what makes first-user-becomes-admin a sales-conversation
-ending finding, and a fixed 900-second lockout is a defensible,
shippable control plenty of production systems ship as-is. Not
implemented this phase. When it is scoped, it needs:
  - **A persisted lockout-count/tier field** on `AccountLockout`
    (`domain/rate_limit.py`) — the current three fields (`user_id`,
    `locked_until`, `failed_attempts`) have nowhere to record how many
    times an account has been locked before. Requires a schema migration
    to `account_lockouts`.
  - **A tiering policy** — `AccountLockoutService`'s deleted 60/120/300/600s
    table is a reasonable starting point, not a requirement.
  - **A decay rule** — when does the count itself reset? The deleted
    class's answer (only on full eviction after a clean `lockout_window`,
    never on a mere successful login) is the one documented design that
    actually avoided the "attacker who occasionally succeeds resets their
    own escalation" trap — worth preserving as a design note even though
    the code itself is gone.
  - It should be built directly against the live, DB-backed
    `LockoutRepository`/`RecordFailedAuthentication` family — never a
    revival of `AccountLockoutService`'s in-memory design, which is
    structurally incompatible with a multi-process deployment (see the
    carried-over-conclusion pattern's fifth instance, above).

## Phase 4 — real-database incident: `~/.kingsec/kingsec.db` migrated unexpectedly

**What happened.** While applying Phase 4's migration to the real
`C:\kingsec-e2e\kingsec.db` (approved, backed up, applied correctly), a
read-only check of the separate real developer database at
`~/.kingsec/kingsec.db` (which no Phase 4 work was ever supposed to touch)
found it had ALSO been migrated to head `289b5978e448` — `alembic_version`
matched, and the new `authorization_grants` table existed there too,
written at 11:25 AM that day, roughly 50 minutes before the intended
migration ran. Content was minimal and untouched by data loss: exactly 1
pre-existing assessment row (unchanged, `authorization_id` NULL),
`authorization_grants` empty (0 rows) — a real schema change with no data
impact.

**The Phase 1 precedent** (Backlog item 1, above): an env-file `source`
with an unquoted path containing spaces silently dropped a
`KINGSEC_STORAGE__DATA_DIR` override during Phase 1 setup, and
`kingsec-migrate` ran against this exact same real `~/.kingsec/kingsec.db`
instead of the intended isolated directory. That incident was caught,
backed up (`kingsec.db.bak-phase1`), and confirmed to have caused no data
loss. This is the second time the same real database has been reached by
a migration it was never meant to receive — different mechanism, same
underlying shape: something resolved KingSec's real default data
directory instead of an explicitly isolated one.

**What was ruled out** (all confirmed directly, not inferred): every
`alembic upgrade`/`revision` command run this session used an explicit
`ALEMBIC_DATABASE_URL` pointing at either a scratch file or, for the real
apply, explicitly `C:/kingsec-e2e/kingsec.db` — never the default. Every
composition-root smoke test (`create_wired_application()`) explicitly set
`KINGSEC_STORAGE__DATA_DIR` to a fresh `tempfile.mkdtemp()` path. No CLI or
server process was run against default settings at any point.

**Test-suite investigation, in two designs:**

*First design (rejected after empirical proof it was wrong):* patched
`StorageSettings.data_dir`'s `default_factory` directly, to raise the
moment the value was even COMPUTED, regardless of whether anything
subsequently used it. Run against the full suite: **451 failures across
47 files** - all the same error, confirmed via grep with no other cause
mixed in. Investigating why revealed the design flaw: pydantic eagerly
evaluates every field's default whenever `Settings()`/`StorageSettings()`
is constructed, including in tests built entirely from in-memory fakes
that never touch a real database at all (representative case:
`test_session_api.py`'s `app()` fixture, which needs `Settings()` only
for unrelated JWT configuration). Confirmed empirically: constructing
`StorageSettings()` against a controlled tmp `HOME` creates nothing on
disk. **Computing a path string is not the hazard; opening or migrating a
database there is** - all 451 were false positives, and would have
required touching 47 files (3 of them this engagement's own Phase 4 test
files) to silence a harmless computation. The lesson: a guard belongs at
the point of the real side effect, not at every place a value merely
passes through.

*Second design (kept):* reading the actual code confirmed the real side
effect - both `build_sqlite_url()`
(`infrastructure/persistence/database.py`, the app-wiring path) and
`_resolve_database_url()` (`alembic/env.py`, the migration path) call
`data_dir.mkdir(parents=True, exist_ok=True)` on the settings-derived
fallback. The relocated guard (`tests/conftest.py`,
`_forbid_real_home_database`) patches `build_sqlite_url` directly: raises,
naming the real path, if the settings-derived `data_dir` resolves to
`Path.home() / ".kingsec"`, before the `mkdir` or URL construction
happens. The explicit `url=` path into `create_database_engine()` (what
nearly every test already uses) never calls `build_sqlite_url` and is
untouched. `alembic/env.py` cannot safely be imported in-process to patch
the same way (its module bottom unconditionally runs
`run_migrations_online()`/`_offline()` on import, expecting Alembic's own
script-runner context) - moot in practice, since every migration
invocation in this codebase, including every test, goes through it
exclusively via subprocess, never in-process. The subprocess path is
guarded separately: `tests/integration/test_alembic_migrations.py`'s
`_run_alembic()` helper had one call site
(`TestSingleHead.test_exactly_one_head`, calling `_run_alembic("heads")`
with no URL) that silently inherited ambient environment instead of an
isolated one - `database_url` is now a required parameter, not
optional-defaulting, closing that gap structurally rather than only at
that one call site. Empirically ruled out as the actual mechanism before
being fixed: `alembic heads` against a controlled tmp data dir creates no
database file at all.

Full suite with the relocated guard: **0 errors, 0 failures**, same 4357
tests, 1 unrelated skip - confirms nothing in the suite opens a database
at the real default location.

**What could not be identified.** With the guard passing cleanly, the
11:25 AM write did not originate from this test suite. Per instruction,
this is recorded as **unidentified**, not attributed to a suspected
cause. `~/.kingsec/kingsec.db` itself was left untouched throughout this
investigation - still at head `289b5978e448` with its one pre-existing
row and empty `authorization_grants` table, deliberately not downgraded
or cleaned up, since doing so risks more than the harmless state it is
already in.

**Open, not closed:** Backlog item 1 (above) - "an override that fails to
resolve silently falls back to the default instead of failing loudly" -
remains unresolved at the production-code level. The guard built here is
test-only.

**Design constraint (Part 2, rejected as a fix - logged as a rule instead):**
investigating a permanent production-code fix for programmatic migration
invocation found no in-process migration entry point exists anywhere in
this codebase - every invocation, including `kingsec-migrate` itself,
goes through subprocess. Building one anyway (e.g. an
`apply_migrations_to(database_url)` function) would have been a function
with zero callers, added to prevent something nobody does - the same
half-built shape as `historical_scope_note`, the fifteen inert settings,
and the unenforced license gates: infrastructure for a hazard with no
reachable path. Not shipped. Recorded instead as a constraint for
whenever this changes: **any in-process migration entry point added in
the future must take an explicit `database_url` with no ambient
fallback to `KINGSEC_STORAGE__DATA_DIR`/the real default - this is a
requirement on that future code, not a TODO to write it now.**
