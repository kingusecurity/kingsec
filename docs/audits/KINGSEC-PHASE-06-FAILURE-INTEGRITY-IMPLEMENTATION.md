# KingSec Phase 06 — Scanner Failure Integrity: Implementation

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`) — unchanged since Phase 01–05; all five remain uncommitted in the working tree.
**Scope:** Implement exactly Phase 05's decision (Option A, one policy-table row). No other change.

---

## 1. Baseline and Phase 01–05 Integrity Check

- Branch: `main`. Commit: `4f4b666`.
- Phase 01–05 markers re-verified directly against current code before any change:
  - `worker_routes.py`: `dependencies=[Depends(require_admin)]` present.
  - `distributed_routes.py`: `_require_admin(user)` present at all 4 call sites.
  - `dto.py` / `schemas.py` / `routes.py`: `failure_reason` present.
  - `_support.py`: `safe_failure_message()` present, applied at both `.fail()` call sites.
- Full backend suite before this phase's change: **2,792 passed, 0 failed, 0 errors, 0 skipped** (JUnit XML, 127.5s).
- **Phases 01–05 remain uncommitted.** This is now true for **six** consecutive phases — restated per §6's explicit instruction. Nothing in this repository's git history reflects any of this remediation programme's work.
- **After the fix:** see Section 8 for the final count.

**VERIFIED.**

---

## 2. §2.1 Control-Flow Trace — Resolved

Re-traced `_execute_scan()` (`submit_assessment.py`, current file, not recalled) against `test_scan_error_marks_assessment_failed`'s exact setup (`test_submit_assessment.py:258-283`):

- The test constructs `SubmitAssessment(assessments=repo, scanner=_FailingScanner(), job_runner=job_runner)` — **no `execution_engine`, no `scanner_executor`** (both default to `None`).
- With both `None`: line 235's `elif execution_engine is not None:` is false; line 239's `if execution_engine is not None:` is false; line 243's `if scanner_executor is not None:` is false; line 253's `elif scanner_ids is not None:` is false (`scanner_ids` stays `None` — no profile is set on `_make_assessment()`). Control falls to the final `else: findings = list(scanner.scan(assessment.target))` — a **direct, unwrapped call** to `_FailingScanner.scan()`, which raises `ConnectionError` immediately.
- That exception propagates straight out of the `try` block (nothing between it and the `except Exception as exc:` at line 301 can catch it — the block that builds `ran_summaries` and calls `.complete()` is never reached at all) and is caught by the use case's own outer `except`, which calls `assessment.fail(safe_failure_message(exc))`.

**This confirms two genuinely distinct control-flow paths through `_execute_scan()`:**

- **Path A — `scanner_executor is not None`** (the only path any real production request ever takes, per `composition.py`'s wiring, re-confirmed in Phase 05 §4/§7): `ScannerOrchestrator.execute_all()` swallows every plugin-level exception internally and never raises to the use case. This is the path the defect lives on, and the only path this fix touches.
- **Path B — `scanner_executor is None`** (test-only, e.g. `test_scan_error_marks_assessment_failed` and several others in `test_submit_assessment.py`): a bare scanner double's exception propagates directly to the use case's own `except`, reaching `.fail()` by a mechanism that predates this phase and needs no change.

**My new conditional sits entirely inside the `if execution_engine is not None:` block** (Section 5), which Path B's control flow never reaches — the exception has already exited the `try` block before that line would execute. **`test_scan_error_marks_assessment_failed` and every other Path-B test are structurally unaffected by this fix** — confirmed empirically in Section 8 (all pre-existing `test_submit_assessment.py`/`test_start_assessment.py` tests still pass, unmodified).

**Scope decision, explicit:** this fix is scoped to Path A only, matching Phase 05's own reachability finding that Path A is the only live path. Path B's behavior is stated, not changed.

**VERIFIED.**

---

## 3. §2.2 Timing Confirmation — Explicit, Not Assumed

Re-read `ScannerOrchestrator.execute_all()` (`orchestrator.py:108-137`) in full:

```python
for plugin in plugins:
    ...
    try:
        result = self.execute(plugin, target, config)
        results.append(result)
        if engine is not None and tid is not None:
            engine.complete_scanner(tid, plugin_id.value, ...)
    except Exception as exc:
        ...
        if engine is not None and tid is not None:
            engine.fail_scanner(tid, plugin_id.value, str(exc))

return tuple(results)
```

**Confirmed, not assumed:** a plain, synchronous `for` loop — no `async`, no `threading`, no `concurrent.futures`, no `break`/`continue`/early `return` anywhere in the loop body. Every plugin's iteration ends with exactly one of `engine.complete_scanner(...)` or `engine.fail_scanner(...)` called synchronously, in-line, before the loop advances to the next plugin. The function's single `return` statement is reached only after every plugin has been processed. Therefore, by the time `_execute_scan()`'s `execution_engine.get_state(tracking_id)` call (`submit_assessment.py`, inside the block this fix modifies) runs — which happens strictly after `scanner_executor.execute_all()` has already returned — **every `ScannerProgress` entry is guaranteed to hold a terminal status** (`"completed"` or `"failed"`; pre-planned `"skipped"` entries are added separately and were never `"running"`/`"pending"` to begin with). A `"running"`/`"pending"` entry surviving to this point is structurally unreachable.

**The "all attempted scanners failed" predicate**, defined precisely (implemented in Section 5): `attempted = [s for s in all_summaries if s.status != "skipped"]`; `all_failed = bool(attempted) and all(s.status == "failed" for s in attempted)`. This is naturally fail-closed by construction — it does not special-case `"running"`/`"pending"`; any status other than exactly `"failed"` simply fails the `all(...)` check, so even in a hypothetical future where a non-terminal status did leak through, it would correctly NOT be treated as failed (defaulting to the safe `COMPLETED` outcome) rather than being misread as either failed or completed by accident.

**VERIFIED.**

---

## 4. Reproduction — Verbatim Pre-Fix Test Failure Output

Both new test files were written first and run against the unmodified codebase.

**`tests/unit/application/test_scanner_failure_policy.py`** (10 tests, real `ScannerOrchestrator` + `AssessmentExecutionEngine` + `SubmitAssessment` — Path A):

```
tests\unit\application\test_scanner_failure_policy.py FFFF......

================================== FAILURES ===================================
____ TestAllAttemptedScannersFailed.test_all_failed_transitions_to_failed _____
    assert result.status == AssessmentStatus.FAILED
E   AssertionError: assert <AssessmentStatus.COMPLETED: 'completed'> == <AssessmentStatus.FAILED: 'failed'>
E    +  where <AssessmentStatus.COMPLETED: 'completed'> = Assessment(id='asmt-...', status=completed, findings=0).status

__ TestAllAttemptedScannersFailed.test_all_failed_reason_names_the_scanners ___
    assert result.failure_reason is not None
E   AssertionError: assert None is not None

_ TestAllAttemptedScannersFailed.test_all_failed_reason_contains_no_raw_exception_text _
    assert result.failure_reason is not None
E   AssertionError: assert None is not None

_ TestAllAttemptedScannersFailed.test_single_scanner_failing_also_transitions_to_failed _
    assert result.status == AssessmentStatus.FAILED
E   AssertionError: assert <AssessmentStatus.COMPLETED: 'completed'> == <AssessmentStatus.FAILED: 'failed'>

4 failed, 6 passed in 0.32s
```

(The 6 passes, pre-fix, are the "unchanged behavior" rows: some-failed/some-succeeded ×2, all-succeeded ×2, empty-attempted-set, and — added slightly after the initial run, see Section 7 — all-preplanned-skips. All 6 already passed before the fix because the current code's unconditional `COMPLETED` is already correct for those rows.)

**`tests/integration/adapters/inbound/web/test_scanner_failure_http_boundary.py`** (2 tests, real HTTP boundary via `TestClient` + real routes):

```
tests\integration\adapters\inbound\web\test_scanner_failure_http_boundary.py FF

_ TestAllFailedVisibleThroughRealHttpGet.test_get_assessment_shows_failed_status_and_populated_reason _
    assert body["status"] == "failed"
E   AssertionError: assert 'completed' == 'failed'

_ TestExecutionStatusErrorFieldSanitized.test_raw_exception_text_does_not_reach_execution_status_response _
    assert "internal-scanner.corp.local" not in raw
E   assert 'internal-sc...r.corp.local' not in "{'assessmen...sage': None}"
E     'internal-scanner.corp.local' is contained here:
E        refused: internal-scanner.corp.local:9200", 'skipped_reason': None}], ...

2 failed, 1 warning in 1.58s
```

Both failures captured live, verbatim, from real runs against unmodified code — not inferred.

**VERIFIED.**

---

## 5. Fix Implemented

### 3.1 / 3.2 — the main fix (`_support.py`, `submit_assessment.py`)

**`src/kingsec/application/_support.py`** — new helper, alongside `safe_failure_message()`:

```python
def compose_all_scanners_failed_message(failed_scanners: Sequence[ScannerRunSummary]) -> str:
    """... Names and counts only - never a per-scanner skipped_reason/error
    string. Those are recorded by engine.fail_scanner() from a raw str(exc)
    ... and have not been run through safe_failure_message()'s split, so
    composing them in here would reopen the same class of leak Phase 03
    closed for the other two .fail() call sites. ..."""
    names = [s.name for s in failed_scanners]
    if len(names) == 1:
        return f"The configured scanner failed to complete: {names[0]}. No results are available for this assessment."
    return (
        f"All {len(names)} configured scanners failed to complete: "
        f"{', '.join(names)}. No results are available for this assessment."
    )
```

**`src/kingsec/application/submit_assessment.py`** — the completion-decision conditional, replacing the unconditional `assessment.complete()`:

```python
        failed_scanners: tuple[ScannerRunSummary, ...] = ()
        if execution_engine is not None:
            state = execution_engine.get_state(tracking_id)
            ran_summaries = tuple(...)  # unchanged
            all_summaries = ran_summaries + preplanned_skips
            assessment.record_scanner_summary(all_summaries)

            attempted = tuple(s for s in all_summaries if s.status != "skipped")
            if attempted and all(s.status == "failed" for s in attempted):
                failed_scanners = attempted

        if failed_scanners:
            assessment.fail(compose_all_scanners_failed_message(failed_scanners))
        else:
            assessment.complete()
        assessments.save(assessment)
```

`failed_scanners` defaults to `()` (falsy) and is populated only inside the `execution_engine is not None` branch, only when the predicate holds. This means: Path B (Section 2) never touches this code at all (it exits the `try` block earlier via a raised exception); Path A with anything other than "every attempted scanner failed" leaves `failed_scanners` empty and calls `.complete()` exactly as before — **zero behavior change for 5 of the 6 policy rows**, by construction, not by a parallel set of extra conditions.

### 3.3 — the independent fix (`execution_routes.py`)

**`src/kingsec/adapters/inbound/web/execution_routes.py`** — sanitizes the one field named in Phase 05 §8's finding:

```python
def _sanitize_scanner_error(raw: str | None) -> str | None:
    """... By the time it reaches this layer the original exception's type
    is gone, so there is no way to tell a safe, developer-authored message
    from an unvetted one ... the only fail-closed option is to treat any
    recorded error as unvetted and collapse it to the same generic safe
    fallback safe_failure_message() uses for its own "anything else" case."""
    if raw is None:
        return None
    return KingSecError.default_user_message
```

Applied at the one call site: `"error": _sanitize_scanner_error(sp.error)` in `_scanner_progress_to_dict()`. `skipped_reason` is deliberately left untouched — it is only ever populated from the `ExecutionPlanner`'s own developer-authored `plan.warnings`/`e.reason` text (pre-execution skips), which is safe by the same `ApplicationError`-is-safe-by-construction reasoning `safe_failure_message()` already applies elsewhere; it is not derived from a raw caught exception the way `sp.error` is.

**A finding beyond what was asked, reported per ground rule #7 rather than silently fixed:** while implementing 3.3, this investigation found that the identical raw, unsanitized string also reaches a **second** sink that Phase 05 §8 did not name: `submit_assessment.py`'s own `ran_summaries` builder sets `skipped_reason=p.skipped_reason or p.error` — for a failed scanner, `p.skipped_reason` is `None`, so this evaluates to the same raw `p.error` text, which flows into `assessment.scanner_summary` and is exposed today via `GET /api/v1/assessments/{id}`'s own `scanner_summary[].skipped_reason` field (confirmed live in Phase 04 §6 script 3's own captured output: `'skipped_reason': "unexpected error in plugin 'nuclei': [WinError 193] %1 is not a valid Win32 application"`). **This second sink is NOT fixed by this phase's 3.3 change** (which only touches `execution_routes.py`) and is **not fixed by 3.1/3.2 either** (which only changes the completion decision, not what gets recorded). It is reported here as a new finding for a future phase, not fixed unilaterally, per ground rule #7 — fixing it correctly would most naturally mean sanitizing at the true source (`orchestrator.py:135`'s `engine.fail_scanner(tid, plugin_id.value, str(exc))` → `safe_failure_message(exc)`), which touches shared infrastructure beyond what this phase's §3.3 scoped to `execution_routes.py`, and is exactly the kind of decision this program's phase structure exists to make deliberately rather than as a drive-by. **Severity: same reasoning as Phase 05 §8 — Low–Medium, ownership-gated (same `check_assessment_access`-equivalent protection applies to the main assessment GET route), not a cross-user leak, but a real violation of the codebase's own stated safety principle, now confirmed to exist on two response surfaces instead of one.**

**VERIFIED.**

---

## 6. The "All Attempted Failed" Predicate

**Exact definition:** given `all_summaries = ran_summaries + preplanned_skips` (every `ScannerRunSummary` recorded for this assessment, both live-executed and pre-planned):

```python
attempted = tuple(s for s in all_summaries if s.status != "skipped")
all_failed = bool(attempted) and all(s.status == "failed" for s in attempted)
```

- **Pre-planned skips:** excluded by the `s.status != "skipped"` filter — both `preplanned_skips` entries (always `status="skipped"`) and any live-recorded `"skipped"` entry from `state.scanner_progress` are removed before the predicate runs. A scanner that was never attempted cannot contribute to "attempted... failed."
- **Non-terminal statuses:** handled by construction, not by a special case — `all(s.status == "failed" for s in attempted)` only matches the literal string `"failed"`; anything else (including a hypothetical, structurally-unreachable `"running"`/`"pending"`, per Section 3's confirmation) makes the predicate `False`, defaulting to `COMPLETED`. Fails closed without needing an explicit non-terminal-status branch.
- **The empty set:** `bool(attempted)` is `False` for an empty tuple, short-circuiting `all(...)` (which would otherwise vacuously return `True` for an empty iterable — confirmed as the exact bug the prompt warned was most likely). An assessment with zero attempted scanners (e.g., every compatible scanner was pre-planned-skipped, or no plugin registry entries matched the target at all) **cannot** be misclassified as `FAILED`.

**VERIFIED**, and tested directly (Section 7).

---

## 7. Tests Added, By Class and Purpose

**`tests/unit/application/test_scanner_failure_policy.py`** (10 tests):

| Class | Test | Purpose |
|---|---|---|
| `TestAllAttemptedScannersFailed` | `test_all_failed_transitions_to_failed` | 2 of 2 scanners fail → `FAILED`. |
| | `test_all_failed_reason_names_the_scanners` | `failure_reason` contains both scanner display names. |
| | `test_all_failed_reason_contains_no_raw_exception_text` | `failure_reason` excludes the raw exception message, host, and port. |
| | `test_single_scanner_failing_also_transitions_to_failed` | 1 of 1 scanner fails → `FAILED` (the trivial "all" case). |
| `TestPartialFailureStaysCompleted` | `test_some_failed_some_succeeded_with_findings_stays_completed` | Policy row 4 — unchanged. |
| | `test_some_failed_some_succeeded_zero_findings_stays_completed` | Policy row 5 — the row explicitly flagged as most likely to regress accidentally. |
| `TestAllSucceededUnchanged` | `test_all_succeeded_zero_findings_stays_completed` | Policy row 2 — unchanged. |
| | `test_all_succeeded_with_findings_stays_completed` | Policy row 1 — unchanged. |
| `TestEmptyAttemptedSetGuard` | `test_no_compatible_plugins_stays_completed_not_failed` | The vacuous-truth guard (Section 6), zero plugins registered. |
| `TestAllPreplannedSkipsStayCompleted` | `test_all_scanners_preplanned_skipped_stays_completed` | Policy row 6 — profile-driven skips, unchanged. |

**`tests/integration/adapters/inbound/web/test_scanner_failure_http_boundary.py`** (2 tests):

| Class | Test | Purpose |
|---|---|---|
| `TestAllFailedVisibleThroughRealHttpGet` | `test_get_assessment_shows_failed_status_and_populated_reason` | The Phase 03 `failure_reason` field now genuinely carries this outcome, through the real route. |
| `TestExecutionStatusErrorFieldSanitized` | `test_raw_exception_text_does_not_reach_execution_status_response` | 3.3's independent fix, real HTTP boundary. |

All 12 use the real production wiring shape (real `ScannerOrchestrator`, real `InMemoryPluginRegistry`, real `AssessmentExecutionEngine`, real `SubmitAssessment`) rather than `dependency_overrides` bypassing the mechanism under test, matching Phases 01–03's established standard.

**VERIFIED.**

---

## 8. Full Test Results

**New tests alone:** 12 passed (10 + 2, confirmed by direct `pytest` runs in Sections 4/9).

**New tests + all pre-existing `submit_assessment.py`/`start_assessment.py` tests, together** (proving Section 2's Path-B-is-unaffected claim empirically, not just by trace):
```
36 passed in <1s
```
(10 new policy tests + 2 new HTTP tests + 16 existing `test_submit_assessment.py` tests + 8 existing `test_start_assessment.py` tests.)

**Complete backend test suite, after the fix** (JUnit XML):
```
tests="2804" errors="0" failures="0" skipped="0" time="126.078s"
```
2,804 = the 2,792-test Phase-05-ending baseline + this phase's 12 new tests, exactly matching the required arithmetic. **No existing test failed or needed investigation for reliance on the old behavior** — the fix is additive/restrictive on exactly one previously-unguarded path.

**Static checks:**
- `ruff check` on all 5 changed/added files (`_support.py`, `submit_assessment.py`, `execution_routes.py`, and both new test files): clean after two trivial auto-fixes (import ordering, one unused import) — zero logic changes from the auto-fix.
- `mypy` on the 3 changed source files: `Success: no issues found in 3 source files`.

**VERIFIED.**

---

## 9. Files Changed

| File | Why |
|---|---|
| `src/kingsec/application/_support.py` | New `compose_all_scanners_failed_message()` helper (Section 5). |
| `src/kingsec/application/submit_assessment.py` | The completion-decision conditional (Section 5) — the main fix. |
| `src/kingsec/adapters/inbound/web/execution_routes.py` | `_sanitize_scanner_error()` (Section 5) — the independent 3.3 fix. |
| `tests/unit/application/test_scanner_failure_policy.py` | New: 10 policy-table regression tests. |
| `tests/integration/adapters/inbound/web/test_scanner_failure_http_boundary.py` | New: 2 HTTP-boundary regression tests. |

No other file was modified. Confirmed via `git status`/`git diff --stat` immediately before writing this report — every other Phase 01–05 file shows zero additional changes this phase.

**VERIFIED.**

---

## 10. Policy Conformance

| Row | Status / `failure_reason` | Proving test |
|---|---|---|
| All succeeded, findings > 0 | `COMPLETED` / `null` | `TestAllSucceededUnchanged::test_all_succeeded_with_findings_stays_completed` |
| All succeeded, zero findings | `COMPLETED` / `null` | `TestAllSucceededUnchanged::test_all_succeeded_zero_findings_stays_completed` |
| **All attempted scanners failed** | **`FAILED`** / **non-null, scanner-name-based** | `TestAllAttemptedScannersFailed` (4 tests) + `TestAllFailedVisibleThroughRealHttpGet` (HTTP boundary) |
| Some failed, some succeeded, findings > 0 | `COMPLETED` / `null` | `TestPartialFailureStaysCompleted::test_some_failed_some_succeeded_with_findings_stays_completed` |
| Some failed, some succeeded, zero findings | `COMPLETED` / `null` | `TestPartialFailureStaysCompleted::test_some_failed_some_succeeded_zero_findings_stays_completed` |
| All pre-planned skips, none attempted | `COMPLETED` / `null` | `TestAllPreplannedSkipsStayCompleted::test_all_scanners_preplanned_skipped_stays_completed` |
| *(guard)* Empty attempted set | `COMPLETED` / `null` | `TestEmptyAttemptedSetGuard::test_no_compatible_plugins_stays_completed_not_failed` |

Every row in Phase 05/06's table has a direct, named proving test. **VERIFIED.**

---

## 11. What This Phase Does NOT Fix

- **The advisory signal for the partial-failure rows** (rows 4 and 5 above) — explicitly a product decision per Phase 05 §11.1, unresolved and out of scope here. `scanner_summary` is accurate for these rows, exactly as it was before this phase; no new top-level signal was added. **Nobody should read this phase as having solved the partial case — it has not, deliberately.**
- **The second unsanitized-error sink**, newly found while implementing 3.3 (Section 5): `AssessmentResponse.scanner_summary[].skipped_reason` on the *main* assessment endpoint carries the same raw, unvetted text `execution_routes.py`'s `error` field used to. Reported, not fixed, per ground rule #7.
- `start_assessment.py` — confirmed unreachable (Phase 05 §7), untouched, per explicit instruction.
- Any `ScannerPort`/`ScannerExecutor` contract change (Option B2) — deferred per Phase 05's decision.
- Any `AssessmentStatus` change — `PARTIAL` remains rejected.
- The 9 adapter guard clauses and the `_logger.debug`/`_logger.warning` parser inconsistency — both explicitly out of scope, unchanged.
- Frontend work — Phase 03 §10's missing `isFailed` branch and TS `failure_reason` field remain unbuilt; this phase's fix is now even more valuable to build against (a real all-failed assessment now genuinely reaches `FAILED` for the frontend to eventually render) but no frontend file was touched.
- Deleting `StartAssessment` — product decision, untouched.

---

## 12. Deferred Audit Findings

All other audit findings remain intentionally untouched because this task is Phase 06 only, scoped to exactly Phase 05's Option-A decision for the single unambiguous policy row.

---

## Report Path

`docs/audits/KINGSEC-PHASE-06-FAILURE-INTEGRITY-IMPLEMENTATION.md`
