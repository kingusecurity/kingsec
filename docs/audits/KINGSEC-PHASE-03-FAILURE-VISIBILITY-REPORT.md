# KingSec Phase 03 — Assessment Failure Visibility Remediation

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`) — unchanged since Phase 01/02; both remain uncommitted in the working tree.
**Scope:** Assessment failure_reason visibility only, per `Downloads/KINGSEC-PHASE-03-PROMPT.md`'s strict scope limit.

---

## 1. Baseline

- Branch: `main`. Commit: `4f4b666`.
- `git status` before any Phase 03 change: Phase 01 (`worker_routes.py` + its test file) and Phase 02 (`distributed_routes.py` + its test file) both present, uncommitted, unmodified. Re-verified explicitly:
  - `worker_routes.py`: `dependencies=[Depends(require_admin)]` present at the router declaration — intact.
  - `distributed_routes.py`: `_require_admin(user)` present at all 4 fixed call sites — intact.
- Full backend `pytest` suite before any Phase 03 change: **2,770 passed, 0 failed, 0 skipped, 0 errors** — exactly Phase 02's ending state, confirming Phase 01 and Phase 02 are both intact going into this phase.
- Relevant existing tests identified: `tests/integration/persistence/test_assessment_repository.py::TestMapping::test_round_trip_preserves_all_fields` already asserts `loaded.failure_reason == assessment.failure_reason` at the persistence layer and already passes — confirming the audit's claim that the ORM/mapper layer is not where the field is dropped. `tests/unit/application/test_get_and_report.py::TestGetAssessment` exercises `GetAssessment`/`AssessmentView` extensively but never references `failure_reason` at all — confirming the audit's claim of zero DTO/HTTP-layer coverage.

**VERIFIED.**

## 2. Defect Verification, Layer by Layer

Read in the order specified, each claim checked directly against the current code:

| Layer | File | Finding |
|---|---|---|
| Domain | `src/kingsec/domain/assessment.py` | `fail(reason)` (line 259) validates a non-empty reason, transitions to `FAILED`, and sets `self._failure_reason = reason`. The `failure_reason` property (line 187) returns it. **Survives.** |
| ORM | `src/kingsec/infrastructure/persistence/models.py` | `AssessmentORM.failure_reason: Mapped[str \| None]` (line 47), nullable text column. **Survives.** |
| Mappers | `src/kingsec/infrastructure/persistence/mappers.py` | `assessment_to_orm()` (line 183) sets `failure_reason=assessment.failure_reason`; the ORM→domain reconstruction (line 304) sets `failure_reason=orm.failure_reason`. Both directions round-trip. **Survives** — and is already proven by the existing, passing `test_round_trip_preserves_all_fields`. |
| DTO | `src/kingsec/application/dto.py` | `AssessmentView` (line 376, pre-fix) had no `failure_reason` field at all. `from_domain()` (line 389, pre-fix) mapped `assessment_id`, `target`, `status`, `is_authorized`, `created_at`, `findings`, `profile_id`, `scanner_summary` — never `failure_reason`. **Dropped here — root cause, confirmed.** |
| HTTP schema | `src/kingsec/adapters/inbound/web/schemas.py` | `AssessmentResponse` (line 159, pre-fix), `extra="forbid"`, mirrored the same field list as the DTO minus `failure_reason`. Inherits the same omission, as the audit predicted. |
| Route handler | `src/kingsec/adapters/inbound/web/routes.py`, `get_assessment()` (line 466) | Explicitly constructs `schemas.AssessmentResponse(...)` field by field from the DTO result; `failure_reason` was never one of the fields listed (pre-fix). Confirms the drop is total by the time a response is built — not a Pydantic-serialization quirk. |

The audit's claim is confirmed exactly, at exactly the layer it named (`AssessmentView.from_domain()`), with no correction needed at any layer.

**One addition beyond the audit's literal wording, found during this verification and folded into the same fix (not separate scope):** `GET /assessments/{id}/execution/status`'s partial exposure while running, and the frontend's `ExecutionProgressPanel` unmounting on terminal state, were both re-confirmed exactly as the audit described (see Section 10). Also newly identified at this step (carried into Section 5): both real call sites that populate `failure_reason` in the first place (`start_assessment.py`, `submit_assessment.py`) pass a raw, unvetted exception string, which is a related but distinct problem from the DTO drop — addressed in Section 5/6 per Step 4's explicit mandate, not a scope expansion.

**VERIFIED.**

## 3. Reproduction, with Verbatim Pre-Fix Test Failure Output

Per Step 3, three new test files were written FIRST, encoding the intended post-fix behavior, and run against the completely unmodified codebase before any source file was touched.

**DTO + HTTP boundary tests** (`tests/unit/application/test_get_assessment_failure_reason.py`, `tests/integration/adapters/inbound/web/test_assessment_failure_visibility.py`) — real `GetAssessment` use case wired to a real (in-memory) `AssessmentRepository`, an `Assessment` driven to `FAILED` through the real domain `Assessment.fail()` method, retrieved through the real `GET /api/v1/assessments/{id}` route handler (not a hand-rolled fake `ServiceAPI`, which would bypass `from_domain()` — the exact place the bug lives — entirely):

```
tests\unit\application\test_get_assessment_failure_reason.py FFFF
tests\integration\adapters\inbound\web\test_assessment_failure_visibility.py F.FFFFFF

================================== FAILURES ===================================
_ TestAssessmentViewFailureReason.test_failed_assessment_view_includes_failure_reason _
tests\unit\application\test_get_assessment_failure_reason.py:49: in test_failed_assessment_view_includes_failure_reason
    assert view.failure_reason == "scanner subprocess exited with code 1"
           ^^^^^^^^^^^^^^^^^^^
E   AttributeError: 'AssessmentView' object has no attribute 'failure_reason'

_ TestFailureReasonHttpVisibility.test_failed_assessment_http_response_contains_failure_reason _
tests\integration\adapters\inbound\web\test_assessment_failure_visibility.py:123: in test_failed_assessment_http_response_contains_failure_reason
    assert body["failure_reason"] == "scanner subprocess exited with code 1"
           ^^^^^^^^^^^^^^^^^^^^^^
E   KeyError: 'failure_reason'

_ TestFailureReasonHttpVisibility.test_completed_assessment_failure_reason_is_null_not_absent _
tests\integration\adapters\inbound\web\test_assessment_failure_visibility.py:138: in test_completed_assessment_failure_reason_is_null_not_absent
    assert "failure_reason" in body
E   AssertionError: assert 'failure_reason' in {'assessment_id': 'asmt-c03905f2ddf94de582862061ea370344', ...}

=================== 10 failed, 1 passed, 1 warning in 2.75s ===================
```

(The 1 pass, pre-fix, is `test_non_owner_non_admin_cannot_read_the_assessment_at_all` — the existing ownership gate already correctly returns 404 regardless of this fix, so it was expected to pass both before and after.)

**Sanitization tests** (`tests/unit/application/test_assessment_failure_sanitization.py`) — since `safe_failure_message` did not exist yet, this file failed at collection:

```
_ ERROR collecting tests/unit/application/test_assessment_failure_sanitization.py _
ImportError while importing test module '...\test_assessment_failure_sanitization.py'.
tests\unit\application\test_assessment_failure_sanitization.py:34: in <module>
    from kingsec.application._support import safe_failure_message
E   ImportError: cannot import name 'safe_failure_message' from 'kingsec.application._support'
```

All raw output is preserved verbatim above from the actual pre-fix pytest runs (captured to `$CLAUDE_JOB_DIR/tmp/phase03_prefix_repro_dto_http.txt` and `phase03_prefix_repro.txt` during this session).

**VERIFIED.**

## 4. Exposure Policy Determination and Reasoning

**Should `failure_reason` be visible to every authenticated user who can read the assessment, or restricted by role?**

Traced the real access path: `GET /assessments/{id}` requires only `require_viewer` (any authenticated role) at the route level, but the use case (`GetAssessment.execute()`, `src/kingsec/application/use_cases/get_assessment.py`) immediately calls `check_assessment_access(assessment, requesting_user, is_admin)` (`src/kingsec/application/_support.py`), which is a real, working IDOR gate:

```python
def check_assessment_access(assessment, requesting_user, is_admin) -> None:
    if is_admin:
        return
    if assessment.owner_id and assessment.owner_id == requesting_user:
        return
    raise AssessmentNotFoundError(str(assessment.id))
```

This already gates the *entire* `AssessmentView` — target, findings, profile, scanner summary, everything — behind "owner or admin," failing closed (an assessment with no recorded owner is admin-only). `failure_reason` is just one more field on the same view. **Decision: no new restriction.** `failure_reason` inherits the existing owner-or-admin gate automatically by being added to the same `AssessmentView`/`AssessmentResponse` the gate already protects — adding a second, parallel check would duplicate an existing mechanism for no behavioral gain, which Step 6 of the prompt explicitly disallows ("no new authorization framework"). Verified with 3 dedicated tests (Section 10).

**Does the failure reason risk leaking internal detail?**

Every call site that produces the string passed into `Assessment.fail()` was inspected — there are exactly two, both a broad `except Exception as exc:`:

- `src/kingsec/application/use_cases/start_assessment.py:146` (pre-fix): `assessment.fail(str(exc))`
- `src/kingsec/application/submit_assessment.py:305` (pre-fix): `assessment.fail(str(exc))`

Both catch **any** exception, including ones from scanner subprocess execution, network calls, and filesystem access that no developer ever vetted for safe display — `str(exc)` on those can carry exactly what the prompt names: absolute paths (`FileNotFoundError: ... '/opt/scanners/nmap/nmap.xml'`), internal hostnames (`ConnectionError: Connection refused: internal-scanner-host.corp.local:9200`), subprocess command lines, etc.

However, not every exception reaching that `except` is unvetted. Two existing, unmodified tests (`test_start_assessment.py::test_required_scanner_unavailable_fails_cleanly_without_scanning`, `test_submit_assessment.py::test_required_scanner_unavailable_fails_cleanly_without_scanning`) already assert that a specific message — `"'Nmap' is not installed"` — appears **verbatim** in `failure_reason`. That message comes from `ExecutionPlanUnsatisfiedError`, a subclass of `kingsec.application.errors.ApplicationError`: a small, deliberately-authored hierarchy of business-rule exceptions (not `kingsec.shared.errors.KingSecError` — a separate hierarchy) that the application layer raises intentionally, with a message a developer wrote as part of normal control flow. That message is safe by construction, the same way `KingSecError.user_message` is safe by construction (`shared/errors/base.py`'s own docstring: `message` is rich internal detail, `user_message` is the safe text — "Never leak internals ... that is reconnaissance for an attacker"). Collapsing `ApplicationError` messages to a generic string would have both broken these two legitimate, currently-passing tests **and** defeated the entire point of this phase (making genuine, safe failure detail legible).

**Decision:** the boundary is not "KingSecError vs. not" but "an exception type the application layer deliberately defined and raises with an intentional message" vs. "everything else":

```
KingSecError      -> exc.user_message               (already the safe half of an existing split)
ApplicationError  -> str(exc)                        (developer-authored, safe by construction)
anything else     -> KingSecError.default_user_message  (unvetted; assume unsafe)
```

**Does the existing structured-logging redaction processor apply to this value?**

No — verified by reading `src/kingsec/infrastructure/logging/redaction.py` in full. `redact_processor` is a `structlog` processor registered in the logging pipeline; it only runs on structured log events, never on values flowing through the domain → DTO → HTTP response path. `failure_reason` never passes through it. This confirms the audit's suspicion exactly: the exposed string needs its own sanitization, independent of logging. **Sanitization is required and is in scope for this phase, per the prompt's explicit Step 4 mandate.**

**VERIFIED.**

## 5. Information-Disclosure Analysis and Sanitization Applied

Added `safe_failure_message(exc: BaseException) -> str` to `src/kingsec/application/_support.py` (the existing home for small, shared application-layer helpers — already houses `check_assessment_access`), implementing exactly the three-branch policy from Section 4. No new exception hierarchy, no new framework — it reuses the two hierarchies (`KingSecError`, `ApplicationError`) that already exist in this codebase.

Applied at both `.fail()` call sites — the only two places in the codebase that construct a `failure_reason` from an exception:

- `src/kingsec/application/use_cases/start_assessment.py`: `assessment.fail(str(exc))` → `assessment.fail(safe_failure_message(exc))`
- `src/kingsec/application/submit_assessment.py`: `assessment.fail(str(exc))` → `assessment.fail(safe_failure_message(exc))`

**Deliberately left untouched, and noted here rather than silently expanded into:** the same except blocks also build an `AssessmentEvent.message` (`f"Scan failed: {exc}"`) and, in `start_assessment.py`, an `AuditEntry.reason=str(exc)`; `submit_assessment.py` also calls `execution_engine.fail_execution(tracking_id, str(exc))`, which feeds the separate, already-partially-exposed `GET .../execution/status` endpoint. These are different sinks (audit trail, event bus, a different endpoint) with different existing behavior and different audiences (the audit trail and event bus are not directly exposed to end users the way `AssessmentResponse` is). Sanitizing them is not part of the confirmed `failure_reason`/`AssessmentView` defect this phase targets; changing them was not necessary to close that defect, and Step 6 of the prompt ("Do NOT rewrite business logic... beyond the smallest correct fix") counsels against widening the change for a related-but-distinct sink. Flagged as a related observation for a future phase (Section 11).

**VERIFIED — 5 direct unit tests of `safe_failure_message()`'s three branches, plus use-case-level tests proving both call sites use it correctly (Section 7).**

## 6. Fix Implemented

Five files changed, 31 insertions / 5 deletions total:

**`src/kingsec/application/_support.py`** (+24/-1) — new helper:
```python
def safe_failure_message(exc: BaseException) -> str:
    if isinstance(exc, KingSecError):
        return exc.user_message
    if isinstance(exc, ApplicationError):
        return str(exc)
    return KingSecError.default_user_message
```

**`src/kingsec/application/use_cases/start_assessment.py`** (+2/-2): `assessment.fail(str(exc))` → `assessment.fail(safe_failure_message(exc))`; import updated.

**`src/kingsec/application/submit_assessment.py`** (+2/-2): identical change at its own, separate call site; import updated.

**`src/kingsec/application/dto.py`** (+2): `AssessmentView` gains `failure_reason: str | None = None`; `from_domain()` maps `failure_reason=assessment.failure_reason`. Since the domain property is already `None` unless `.fail()` was called, non-failed assessments get `None` automatically — no extra branching needed.

**`src/kingsec/adapters/inbound/web/schemas.py`** (+1): `AssessmentResponse` gains `failure_reason: str | None = None` (required under `extra="forbid"` — an undeclared field would otherwise be silently dropped from the response even if the DTO carried it).

**`src/kingsec/adapters/inbound/web/routes.py`** (+1): `get_assessment()`'s `AssessmentResponse(...)` construction gains `failure_reason=result.failure_reason`.

Both new fields default to `None` and are purely additive to existing schemas — no existing field, request shape, or response-shape assertion changes. Backward compatible.

**VERIFIED.**

## 7. Regression Tests Added, by Class and Purpose

22 new tests, 0 existing tests modified, skipped, weakened, or deleted:

| File | Class | Tests | Purpose |
|---|---|---|---|
| `tests/unit/application/test_get_assessment_failure_reason.py` | `TestAssessmentViewFailureReason` | 4 | DTO-level: FAILED carries the reason; COMPLETED/RUNNING are `None`; special characters survive unmodified. |
| `tests/integration/adapters/inbound/web/test_assessment_failure_visibility.py` | `TestFailureReasonHttpVisibility` | 4 | HTTP-level: same four cases through the real route handler and Pydantic response. |
| `tests/integration/adapters/inbound/web/test_assessment_failure_visibility.py` | `TestFailureReasonInheritsExistingOwnershipGate` | 3 | Non-owner/non-admin still 404s (field never reachable); admin can read another user's reason; owner can read their own. |
| `tests/integration/persistence/test_failure_reason_end_to_end.py` | `TestFailureReasonFullRoundTrip` | 1 | Full chain in one test: `fail()` → real SQLite (`SQLAlchemyAssessmentRepository`) → session-expunge to force a genuine reload → real `GetAssessment` → real HTTP GET. |
| `tests/unit/application/test_assessment_failure_sanitization.py` | `TestSafeFailureMessage` | 5 | Direct unit coverage of all three branches of `safe_failure_message()`. |
| `tests/unit/application/test_assessment_failure_sanitization.py` | `TestStartAssessmentFailureReasonSanitization` | 3 | `start_assessment.py`'s call site: unvetted exception sanitized; `KingSecError` uses its `user_message`; `ApplicationError` preserved verbatim. |
| `tests/unit/application/test_assessment_failure_sanitization.py` | `TestSubmitAssessmentFailureReasonSanitization` | 2 | Same three cases (minus the redundant `KingSecError` case) against `submit_assessment.py`'s own, separate call site. |

4 + 4 + 3 + 1 + 5 + 3 + 2 = 22.

**VERIFIED.**

## 8. Full Test Results

**New Phase 03 tests alone:**
```
22 passed (across the 4 new files listed in Section 7)
```

**New tests + the two pre-existing tests that assert on `ExecutionPlanUnsatisfiedError` text surviving verbatim** (`test_start_assessment.py`, `test_submit_assessment.py`) — run together to prove the sanitization fix does not regress them:
```
43 passed, 1 warning in 2.31s
```

**Complete backend test suite, after the fix** (JUnit XML, `$CLAUDE_JOB_DIR/tmp/phase03_final.xml`):
```
tests="2792" errors="0" failures="0" skipped="0" time="210.280s"
```
2,792 = the 2,770-test Phase-02-ending baseline + this phase's 22 new tests, exactly matching the prompt's required arithmetic. **No existing test failed** — none needed investigation for reliance on the old (broken) behavior. The two tests that legitimately depend on `ApplicationError` text surviving unchanged (Section 4/5) were identified proactively, verified to still pass, and are explicitly documented above rather than silently discovered as failures.

**Static checks:**
- `ruff check .`: clean on every file touched or added this phase. The only remaining findings repo-wide are 9 pre-existing, untracked `src/kingsec/alembic/versions/*__no_changes.py` stray files — a known, pre-existing, unrelated test-hygiene issue (the `test_alembic_migrations.py` autogenerate test writes them on every full-suite run) documented in the source audit and explicitly out of scope for this phase.
- `mypy` on all 6 changed source files: `Success: no issues found in 6 source files`.
- Import-linter (`lint-imports`): not installed in this environment (consistent with the source audit's and Phase 01/02's findings) — not installed for this task, per the "no new toolchain" constraint. The only new cross-module import (`from kingsec.shared.errors import KingSecError` in `_support.py`) is an application-layer file importing from the shared kernel, which `shared/errors/__init__.py`'s own docstring states is deliberately importable from every layer ("this package imports ONLY the standard library... every layer (domain, application, infrastructure) may depend on it").

**VERIFIED.**

## 9. Files Changed

| File | Why |
|---|---|
| `src/kingsec/application/_support.py` | New `safe_failure_message()` helper (Section 5/6). |
| `src/kingsec/application/use_cases/start_assessment.py` | Use the helper at its `.fail()` call site. |
| `src/kingsec/application/submit_assessment.py` | Use the helper at its own, separate `.fail()` call site. |
| `src/kingsec/application/dto.py` | Add `failure_reason` to `AssessmentView` and map it in `from_domain()` — the root-cause fix. |
| `src/kingsec/adapters/inbound/web/schemas.py` | Declare `failure_reason` on `AssessmentResponse` (required under `extra="forbid"`). |
| `src/kingsec/adapters/inbound/web/routes.py` | Pass `failure_reason` through in the `get_assessment()` response construction. |
| `tests/unit/application/test_get_assessment_failure_reason.py` | New: 4 DTO-level tests. |
| `tests/integration/adapters/inbound/web/test_assessment_failure_visibility.py` | New: 7 HTTP-level tests. |
| `tests/integration/persistence/test_failure_reason_end_to_end.py` | New: 1 full-chain SQLite→HTTP test. |
| `tests/unit/application/test_assessment_failure_sanitization.py` | New: 10 sanitization tests. |

No other file was modified. Confirmed via `git diff --stat` and `git status` immediately before writing this report — Phase 01's `worker_routes.py` and Phase 02's `distributed_routes.py` are present with zero additional changes this phase.

**VERIFIED.**

## 10. Frontend Work Required, Scoped But Not Performed

Per Step 7, no frontend file was modified. `ExecutionProgressPanel.tsx` and `AssessmentDetailPage.tsx` were read to scope the follow-on work precisely:

- **`frontend/src/types/api.ts`**: `AssessmentResponse` (line 115) has no `failure_reason` field. Even after this phase's backend fix starts sending the field, the frontend's TypeScript type would not know it exists — it would need `failure_reason: string | null` added before any component could reference it without a type error.
- **`frontend/src/pages/AssessmentDetailPage.tsx`**: derives `isRunning`, `isPending`, `isDraft`, `isCompleted` booleans (lines 29–32) from `assessment.status` — there is no `isFailed` flag and no conditional UI block for the failed state anywhere in the file.
- **`ExecutionProgressPanel`** (imported at line 12) is the *only* component in this page that renders any diagnostic/progress detail, and it is gated by `{(isRunning || isPending) && (...)}}`  (line 129–131) — it unmounts the instant `status` becomes `"failed"`, exactly as the audit described. There is no fallback component that mounts in its place.

**What Phase 04 (or later) would need to do, not performed here:** add `failure_reason` to the TS type; compute an `isFailed` flag; render a new block (e.g. an alert/banner, styled similarly to the already-imported `ErrorState`) when `isFailed`, displaying `assessment.failure_reason`. This is a small, well-localized frontend change — the backend fix in this phase is a precondition for it, not a substitute for it. Until that frontend work happens, a real user still sees only a red status badge in the browser, even though the API now returns the reason correctly (verified directly against `curl`-equivalent HTTP calls in Section 3/8, not just unit-level).

**NOT PERFORMED — scoped only, per Step 7's explicit instruction.**

## 11. What This Phase Does NOT Fix

- **Malformed scanner output silently producing a COMPLETED / zero-findings assessment** (audit defect #4) — a separate defect with a separate root cause (a scanner adapter/parser problem, not an authorization or DTO-mapping problem). Exposing `failure_reason` does **not** fix it, and is not described as fixing it anywhere in this report: an assessment that never enters `FAILED` in the first place has no failure reason to show, regardless of this fix.
- Non-zero scanner exit with partial output treated as success (audit defect #5).
- Finding deduplication, scanner attribution, correlation, risk intelligence.
- Trivy/Semgrep target-type defect.
- Any scanner work of any kind.
- Any authorization work — Phases 01 and 02 remain closed and untouched this phase.
- The frontend rendering work scoped in Section 10.
- Sanitizing the `AssessmentEvent.message`, `AuditEntry.reason`, and `execution_engine.fail_execution()` sinks noted in Section 5 — related to the same underlying exceptions, but different sinks with different audiences, not part of the confirmed `failure_reason`/`AssessmentView` defect this phase targets.

## 12. Deferred Audit Findings

All other audit findings remain intentionally untouched because this task is Phase 03 only.

---

## Phase 03 Recommendation (Do NOT Implement)

The source audit's #4 finding — malformed scanner output silently producing a `COMPLETED` assessment with zero findings, indistinguishable from a genuinely clean scan — is the highest-value next investigation. It sits squarely inside the six-state model Section 4 of the prompt describes (`SUCCESS + ZERO FINDINGS` vs. `SCANNER FAILURE` vs. `PARSER FAILURE`) and is explicitly the state this phase's fix does *not* yet make legible, since an assessment that never transitions to `FAILED` has no `failure_reason` to expose. Recommend a future phase trace exactly where a malformed/empty scanner result is currently treated as "zero findings, success" instead of a distinguishable failure state, using the same verify-before-fix, test-first discipline as Phases 01–03.

## Report Path

`docs/audits/KINGSEC-PHASE-03-FAILURE-VISIBILITY-REPORT.md`
