# KingSec Phase 07 — Scanner Error Sanitization at Source

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`) — unchanged since Phase 01–06; all six remain uncommitted in the working tree.
**Scope:** Sanitize the raw scanner-error string at its true source, closing both known sinks with one change, and reconcile Phase 06's now-redundant sink-level sanitizer.

---

## 1. Baseline and Phase 01–06 Integrity Check

- Branch: `main`. Commit: `4f4b666`.
- Phase 01–06 markers re-verified directly against current code before any change: `worker_routes.py`'s `require_admin` dependency; `distributed_routes.py`'s 4 `_require_admin` call sites; `failure_reason` in `dto.py`/`schemas.py`/`routes.py`; `safe_failure_message()` and `compose_all_scanners_failed_message()` in `_support.py`; the `failed_scanners` conditional in `submit_assessment.py`; Phase 06's `_sanitize_scanner_error()` in `execution_routes.py` (present pre-change, reconciled in Section 7 below).
- Full backend suite before this phase's change: **2,804 passed, 0 failed, 0 errors, 0 skipped** (JUnit XML, 126.0s) — exactly Phase 06's ending state.
- **Phases 01–06 remain uncommitted.** This is now true for **seven** consecutive phases — the largest process risk in this programme, independent of any code defect, restated per §6's explicit instruction. Nothing in this repository's git history reflects any of this remediation programme's work.

**VERIFIED.**

---

## 2. §2.1 Wrapping Trace — Resolved

Re-read `orchestrator.py:63-71` (`execute()`) and `orchestrator.py:36-37` / `application/errors.py` directly, not recalled:

- `ScannerPluginError` (`application/errors.py:36`) is declared `class ScannerPluginError(ApplicationError):` — it sits in the `ApplicationError` hierarchy (`application/errors.py`), **not** `KingSecError` (`shared/errors/`). Two entirely separate hierarchies, confirmed by import: `orchestrator.py:18` imports it from `kingsec.application.errors`.
- **What exception type reaches `execute_all()`'s `except Exception as exc:` at line 128 (feeding `fail_scanner()` at line 135)?** Traced both cases in `execute()`:
  - If a plugin raises `ScannerPluginError` itself, `except ScannerPluginError: raise` (line 67-68) re-raises it **unwrapped, unchanged**. No interpolation occurs on this path.
  - If a plugin raises **anything else** (the common case — a `ScannerExecutionError` from an adapter's guard clause, or a raw stdlib exception), `except Exception as exc:` (line 69, pre-fix) built `ScannerPluginError(f"unexpected error in plugin {id!r}: {exc}")` — **the original exception's `str()` was interpolated directly into the new wrapper's own message**, before this phase's change.
- **What would `safe_failure_message()` return for the pre-fix wrapper, today, given this classification?** Since `ScannerPluginError` is an `ApplicationError`, `safe_failure_message()`'s second branch (`isinstance(exc, ApplicationError): return str(exc)`) applies — and `str(exc)` on the wrapper **already contains the raw original text**, baked in by the interpolation above. **Confirmed exactly as the prompt warned: sanitizing only at line 135 (swapping `str(exc)` for `safe_failure_message(exc)`) would have been a no-op**, because the thing being classified as "safe by construction" was itself carrying unsafe embedded content composed one call-frame earlier.

**This settles the pre-check: the fix must change `execute()`'s wrapping (the interpolation site), not just `execute_all()`'s `fail_scanner()` call.** Section 5 implements this.

**VERIFIED.**

---

## 3. §2.2 Downstream Quality Check

Read `templates.py:629-680` (`_clean_scanner_reason()` / `_scanner_summary()`) directly. A pre-existing function, `_clean_scanner_reason()`, already strips two known framing patterns — `_PLUGIN_WRAPPER_PREFIX` (`^unexpected error in plugin '[^']+':\s*`) and `_ERROR_CODE_PREFIX` (`^\[[A-Z]+-[A-Z]+-\d+\]\s*`) — but does **not** redact anything in the remaining payload text. This was already covered by an existing test (`test_templates.py::TestScannerCoverage::test_internal_error_framing_is_stripped`) for a message that was already safe once the framing was stripped (a timeout message with no paths/hosts) — that existing test is unaffected by this phase (it constructs its `ScannerRunSummary` by hand, never touching `orchestrator.py`).

**Concrete before/after, proven live** (Section 4's reproduction, Section 6):

| Case | Rendered in Scanner Coverage — **before** | Rendered — **after** |
|---|---|---|
| Developer-authored (`ScannerExecutionError("nuclei exited with code 1", ...)`) | `"Nuclei Scanner: not run (nuclei exited with code 1)."` — specific, but this is the exception's raw internal `message`, not its designated-safe `user_message` | `"Nuclei Scanner: not run (The security scan could not be completed.)."` — safe, generic |
| Unvetted (`ConnectionError("Connection refused: internal-scanner.corp.local:9200")`) | `"Nuclei Scanner: not run (Connection refused: internal-scanner.corp.local:9200)."` — **leaks the internal hostname** | `"Nuclei Scanner: not run (An unexpected error occurred. Please try again or contact support.)."` — safe |

**Honest accounting, not overclaimed:** the fix **strictly improves** the unvetted case (closes a real, live leak, proven in Section 4) and is **safety-neutral but specificity-reduced** for the developer-authored case — `ScannerExecutionError`'s raw `message` (e.g. "nuclei exited with code 1") happened to already be safe in practice (no paths/hosts in current adapter code), but `safe_failure_message()` correctly does not trust that by inspection; it uses the class's own designated `user_message`, which for `ScannerError`/`ScannerExecutionError` is the generic `"The security scan could not be completed."` (no adapter currently sets a more specific `user_message=` override). This is the same tradeoff Phase 03 already made for the `.fail()` sinks, applied consistently here — not a new regression, and not something this phase should quietly smooth over. **The fix does not degrade Scanner Coverage into Phase 06 §3.3's mistake** (a single generic string for every case): the two cases above render two genuinely different, correctly-differentiated messages, both proven by test (Section 6).

**VERIFIED**, before/after both confirmed live, not asserted from reasoning alone.

---

## 4. Reproduction — Verbatim Pre-Fix Test Failure Output

Four new test files were written first, spanning orchestrator-unit, HTTP-boundary (both endpoints), and report-rendering layers, then run against unmodified code.

**`tests/unit/infrastructure/scanner/test_orchestrator_error_sanitization.py`** (4 tests, orchestrator-level):
```
FFF.
_ TestExecuteWrappingIsSanitized.test_unvetted_exception_wrapped_message_has_no_raw_text _
    assert "internal-scanner.corp.local" not in str(exc)
E   AssertionError: 'internal-scanner.corp.local' is contained here:
E      refused: internal-scanner.corp.local:9200

_ TestExecuteWrappingIsSanitized.test_kingsec_error_wrapped_message_uses_safe_user_message _
    assert "/opt/scanners" not in str(exc)
E   AssertionError: '/opt/scanners' is contained here:
E     bprocess /opt/scanners/nuclei failed: Permission denied: /etc/nuclei/config

_ TestFailScannerReceivesSanitizedText.test_engine_records_safe_message_not_raw_text _
    assert "internal-scanner.corp.local" not in entry.error
E   AssertionError: 'internal-scanner.corp.local' is contained here: ...

4 failed, 1 passed in 0.22s
```
(The 1 pass is `test_deliberately_raised_scanner_plugin_error_is_preserved_verbatim` — Case 1 from Section 2, already correct pre-fix since no wrapping/interpolation happens on that path.)

**`tests/unit/infrastructure/test_orchestrator_error_logging.py`** (1 test): passed both before and after — a regression *guard*, not a reproduction (logging behavior was never broken; this test exists to prove the fix doesn't accidentally suppress it).

**`tests/integration/adapters/inbound/web/test_scanner_error_sanitization_source_http.py`** (3 tests, real HTTP boundary, both `GET /assessments/{id}` and `GET .../execution/status`):
```
_ TestUnvettedFailureLeaksNowhere.test_neither_endpoint_shows_raw_text _
    assert "internal-scanner.corp.local" not in raw
E   'internal-scanner.corp.local' is contained here:
E      refused: internal-scanner.corp.local:9200"}], 'failure_reason': 'The configured scanner failed to complete: Nuclei Scanner. ...'}

_ TestDeveloperAuthoredFailureSurvives.test_useful_message_reaches_both_surfaces _
    assert 'The security scan could not be completed.' in "unexpected error in plugin 'nuclei': [KS-SCAN-001] nuclei exited with code 1"
E   AssertionError

2 failed, 1 passed, 1 warning in 1.38s
```
(The 1 pass, `TestAllFailedBehaviorStillHolds`, confirms Phase 06's `failure_reason` field was already correctly excluding raw text — the failure here is specifically in the *other* fields of the same response, `scanner_summary`, precisely the second sink Phase 06 §5 named.)

**`tests/integration/reporting/test_scanner_coverage_source_sanitization.py`** (2 tests, real orchestrator → real `Report` → rendered HTML):
```
_ TestScannerCoverageRendersSafely.test_unvetted_failure_renders_generic_fallback_no_hostname _
    assert "internal-scanner.corp.local" not in section
E   'internal-scanner.corp.local' is contained here: refused: internal-scanner.corp.local:9200).</p>

_ TestScannerCoverageRendersSafely.test_developer_authored_failure_renders_useful_safe_message _
    assert "The security scan could not be completed" in section
E   AssertionError: '><h2>Scanner Coverage</h2><p>Nuclei Scanner: not run (nuclei exited with code 1).</p>'

2 failed in 0.70s
```

All captured live, verbatim, from real runs against unmodified code.

**VERIFIED.**

---

## 5. Fix Implemented

**`src/kingsec/infrastructure/scanner/orchestrator.py`** — two changes, both inside `ScannerOrchestrator`:

1. `execute()`'s wrapping (the true source, per Section 2):
```python
except Exception as exc:
    p2 = cast(ScannerPluginPort, plugin)
    raise ScannerPluginError(
        f"unexpected error in plugin {p2.metadata().id.value!r}: {safe_failure_message(exc)}"
    ) from exc
```
The wrapper prefix text (`"unexpected error in plugin '<id>': "`) is deliberately unchanged — it still matches `templates.py`'s existing `_PLUGIN_WRAPPER_PREFIX` regex, so `templates.py` needed zero changes. Only the interpolated tail changed, from the raw `{exc}` to the sanitized `{safe_failure_message(exc)}`.

2. `execute_all()`'s exception handling — sanitized for the product sink, but the **original** exception (via `__cause__`) preserved for the log sink:
```python
except Exception as exc:
    original = exc.__cause__ if exc.__cause__ is not None else exc
    _logger.warning(
        "scanner plugin failed, skipping",
        plugin_id=str(plugin_id),
        error=str(original),
    )
    if engine is not None and tid is not None:
        engine.fail_scanner(tid, plugin_id.value, safe_failure_message(exc))
```
`raise ... from exc` (in `execute()`) sets `__cause__` on the wrapper, so the real original exception is still reachable for logging even though the wrapper's own message is now sanitized. For Case 1 (an already-`ScannerPluginError`, never wrapped), `__cause__` is `None` (unless the original raiser chained one), so the fallback logs `exc` itself — its own deliberately-authored, non-raw message, which is fine to log as-is either way.

**`src/kingsec/adapters/inbound/web/execution_routes.py`** — Section 7.

**VERIFIED**, diffs shown are the actual applied changes.

---

## 6. §3.2 — Second Sink Closure, Proven By Test

`submit_assessment.py`'s `skipped_reason=p.skipped_reason or p.error` (the line Phase 06 §5 named as the second, unaddressed sink) was **not modified this phase**. Per the prompt's explicit instruction, this was confirmed by test, not by reasoning alone:

- `TestUnvettedFailureLeaksNowhere::test_neither_endpoint_shows_raw_text` (Section 4) fails pre-fix specifically because the raw hostname reaches `GET /assessments/{id}`'s `scanner_summary[].skipped_reason` (fed by `p.error`, unchanged code path) — and **passes after the orchestrator-only fix**, with zero changes to `submit_assessment.py`. This is direct proof the second sink closes automatically once `p.error` (populated by `engine.fail_scanner()`, now receiving `safe_failure_message(exc)`) is safe at its own source.
- `TestDeveloperAuthoredFailureSurvives::test_useful_message_reaches_both_surfaces` (Section 4) similarly confirms the *positive* case: the safe, useful message reaches `scanner_summary[].skipped_reason` too, without `submit_assessment.py` needing to know anything changed.

**It did close automatically. No change to `submit_assessment.py` was required or made.**

**VERIFIED.**

---

## 7. §3.3 — The `_sanitize_scanner_error()` Decision

**Decision: removed.**

With source sanitization in place (Section 5), `sp.error` is safe by construction by the time it reaches `execution_routes.py` — Phase 06's blanket `_sanitize_scanner_error()` (which collapsed every non-`None` value to `KingSecError.default_user_message` regardless of what it was) became **redundant** (no unsafe value can reach it anymore) and **actively lossy** (it would flatten an already-safe, already-specific message like `"The security scan could not be completed."` down to the fully generic `"An unexpected error occurred. Please try again or contact support."` a second time) — confirmed live: after implementing Section 5 alone (before touching `execution_routes.py`), `TestDeveloperAuthoredFailureSurvives` still failed with exactly this second-collapse symptom (`'The security scan could not be completed.' in 'An unexpected error occurred...'` → `False`).

**Why "remove" rather than "keep as defence-in-depth, rewritten"?** A defence-in-depth re-sanitization at this layer would need to distinguish safe from unsafe *again*, but by this point in the call chain the original exception's type is permanently gone (Phase 06 §3.3's own stated reason for why it could only collapse everything) — there is no way to rewrite it to "preserve safe messages" without either (a) re-implementing a second, independent judgment of safety with no type information (a heuristic, exactly what Phase 03 rejected in favor of type-based sanitization), or (b) trusting that anything reaching this point is already safe — which is just "remove it" with extra steps. Ground rule #5 explicitly permits removal here, since this is Phase 06's own addition and this phase is chartered to revisit it.

**Proven by test that the safe message survives, per the prompt's explicit requirement:** `TestDeveloperAuthoredFailureSurvives::test_useful_message_reaches_both_surfaces` asserts the exact safe string (`"The security scan could not be completed."`) is present, verbatim, in `GET .../execution/status`'s `scanner_progress[].error` field after removal — passing (Section 4/Section 8).

**VERIFIED.**

---

## 8. Tests Added, By Class and Purpose

| File | Class | Tests | Purpose |
|---|---|---|---|
| `test_orchestrator_error_sanitization.py` | `TestExecuteWrappingIsSanitized` | 3 | The wrapping site itself: unvetted → no raw text; `KingSecError` → safe `user_message`; deliberately-raised `ScannerPluginError` → preserved verbatim (Case 1, unaffected). |
| | `TestFailScannerReceivesSanitizedText` | 1 | `engine.fail_scanner()` receives the sanitized text, not raw. |
| `test_orchestrator_error_logging.py` | `TestLoggingStillReceivesRawDetail` | 1 | The structured log still receives the raw, unsanitized detail — proves §3.1's "logging is unaffected" requirement, via a monkeypatched logger (see the file's own docstring for why: this codebase's `cache_logger_on_first_use=True` makes real-pipeline stream capture and even `structlog.testing.capture_logs()` unreliable for an already-imported module's logger across a shared test session — both were tried and empirically failed before this approach). |
| `test_scanner_error_sanitization_source_http.py` | `TestUnvettedFailureLeaksNowhere` | 1 | Neither `GET /assessments/{id}` nor `GET .../execution/status` leaks raw text — real HTTP boundary, both endpoints, one test. |
| | `TestDeveloperAuthoredFailureSurvives` | 1 | The useful message survives to both surfaces — the test distinguishing this phase from Phase 06 §3.3's blanket collapse. |
| | `TestAllFailedBehaviorStillHolds` | 1 | Phase 06's all-failed → `FAILED` regression check: scanner names present, no raw text in `failure_reason`. |
| `test_scanner_coverage_source_sanitization.py` | `TestScannerCoverageRendersSafely` | 2 | Report-layer Scanner Coverage: generic fallback for unvetted, safe specific message for developer-authored — using real orchestrator-produced summaries, not hand-typed strings. |

10 tests total. All use real production wiring (real `ScannerOrchestrator`, real `AssessmentExecutionEngine`, real `SubmitAssessment`, real HTTP routes via `TestClient`, real `Report.from_assessment()`/`render_report_html()`) rather than mocks bypassing the mechanism under test.

**VERIFIED.**

---

## 9. Full Test Results

**New tests alone:** 10 passed (confirmed in Section 4/6/7's post-fix runs).

**New tests + all existing scanner/reporting/submit_assessment/start_assessment suites, together** (regression check across every surface this phase's change could plausibly affect):
```
tests/unit/infrastructure/scanner/  tests/unit/infrastructure/reporting/
tests/integration/reporting/  tests/integration/scanner/
tests/unit/application/test_submit_assessment.py  tests/unit/application/test_start_assessment.py
→ all passed, 0 failed
```

**Complete backend test suite, after the fix** (JUnit XML):
```
tests="2814" errors="0" failures="0" skipped="0" time="123.710s"
```
2,814 = the 2,804-test Phase-06-ending baseline + this phase's 10 new tests, exactly matching the required arithmetic. **No existing test failed or needed investigation for reliance on the old behavior**, including the pre-existing `test_templates.py::test_internal_error_framing_is_stripped`, which constructs its own `ScannerRunSummary` by hand and never touches `orchestrator.py` — unaffected by construction.

**Static checks:**
- `ruff check` on both changed source files and all 4 new test files: clean after trivial auto-fixes (unused imports left over from an earlier draft of the logging test) — zero logic changes from the auto-fix.
- `mypy` on the 2 changed source files: `Success: no issues found in 2 source files`.

**VERIFIED.**

---

## 10. Files Changed

| File | Why |
|---|---|
| `src/kingsec/infrastructure/scanner/orchestrator.py` | The main fix (Section 5): sanitize at the true source, in both `execute()`'s wrapping and `execute_all()`'s `fail_scanner()` call, while preserving raw detail for the log sink via `__cause__`. |
| `src/kingsec/adapters/inbound/web/execution_routes.py` | Section 7: `_sanitize_scanner_error()` removed; `sp.error` passed through directly, now safe by construction. |
| `tests/unit/infrastructure/scanner/test_orchestrator_error_sanitization.py` | New: 4 orchestrator-level tests. |
| `tests/unit/infrastructure/test_orchestrator_error_logging.py` | New: 1 logging-preservation test. |
| `tests/integration/adapters/inbound/web/test_scanner_error_sanitization_source_http.py` | New: 3 HTTP-boundary tests. |
| `tests/integration/reporting/test_scanner_coverage_source_sanitization.py` | New: 2 report-rendering tests. |

No other file was modified. Confirmed via `git status`/`git diff --stat` immediately before writing this report — every other Phase 01–06 file shows zero additional changes this phase.

**VERIFIED.**

---

## 11. What This Phase Does NOT Fix

- **The advisory signal for partial-failure rows** — still an unresolved product decision (Phase 05 §11.1). Untouched, restated explicitly so nobody mistakes this phase's work (which only touches error-message *content*, not assessment *status* semantics) for progress on that separate, still-open question.
- `start_assessment.py` — confirmed unreachable (Phase 05 §7), untouched.
- Any `ScannerPort`/`ScannerExecutor` contract change (Option B2) — deferred, untouched.
- `AssessmentStatus`/`PARTIAL` — rejected, closed, untouched.
- The 9 adapter guard clauses; the `_logger.debug`/`_logger.warning` parser inconsistency (Phase 04 §10.4) — both explicitly out of scope, unchanged.
- Frontend work — Phase 03 §10's missing `isFailed` branch and TS `failure_reason` field remain unbuilt.
- Deleting `StartAssessment` — product decision, untouched.
- The developer-authored-case specificity tradeoff noted in Section 3 (raw `ScannerExecutionError.message` was sometimes more specific than its `user_message`) — not addressed; adapters could in principle set more specific `user_message=` values per failure mode, but that is a scanner-adapter change, not a sanitization-mechanism change, and is out of scope here.

---

## 12. Deferred Audit Findings

All other audit findings remain intentionally untouched because this task is Phase 07 only, scoped to exactly the source-sanitization fix Phase 06 §5 identified and the reconciliation of Phase 06 §3.3's own addition.

---

## Report Path

`docs/audits/KINGSEC-PHASE-07-SCANNER-ERROR-SANITIZATION-REPORT.md`
