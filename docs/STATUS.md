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

**Branch:** `feat/phase-2b-real-coverage`
**Status:** Task 1 IN PROGRESS. This section covers Task 1's decisions only; Task 2 has not started.

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

Task 2 has not started. Waiting for explicit go-ahead per this round's own instruction ("Then STOP. Report back before starting Task 2").
