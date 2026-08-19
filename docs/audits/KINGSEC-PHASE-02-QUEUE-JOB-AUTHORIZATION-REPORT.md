# KingSec Phase 02 — Distributed Queue / Job Authorization Remediation

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`) — same as Phase 01, since Phase 01's fix remains uncommitted in the working tree, as before.
**Scope:** Distributed queue/job mutation authorization only, per `Downloads/new prompt.txt`'s strict scope limit.

---

## 1. Executive Summary

**Confirmed and fixed.** The audit's finding was reproduced live against the current repository (Step 4, before any code change), the fix was implemented using KingSec's existing RBAC mechanism, and regression coverage now proves both the previously-vulnerable behavior is closed and legitimate Admin access still works.

One material finding beyond the audit's original wording: the audit named 3 vulnerable operations (`retry`, `cancel`, `dead-letter/requeue`). Investigation found a **4th operation with the identical gap** — `GET /api/v1/queue/{entry_id}` (single-entry detail, which returns `payload` and `target`) — justified by direct comparison against the sibling `queue_routes.py`'s own established rule (list/aggregate reads without `payload` stay open; single-entry detail reads that include `payload` require Admin). This 4th operation is fixed as part of this same change, for the same root cause, under the same policy — not scope creep.

## 2. Baseline

- Branch: `main`
- Commit: `4f4b666`
- `git status` before any Phase 02 change: clean except Phase 01's already-verified, intact, uncommitted fix (`worker_routes.py` + its test file) and the same pre-existing, unrelated untracked artifacts noted in Phase 01's report.
- Full backend test suite before any Phase 02 change: **2,740 passed, 0 failed, 0 skipped, 0 errors, 3 warnings, 141.61s** (exactly Phase 01's ending state — confirms Phase 01 is intact going into this phase).
- Relevant existing tests identified: none. Grepped the entire `tests/` tree for any reference to `distributed_routes`, `queue_routes`, `JobQueueRepositoryPort`, `RetryManager`, or `DeadLetterService` — **zero pre-existing test files touch this router at all**, at any layer. This absence of coverage is itself consistent with how the gap shipped unnoticed (the same pattern already observed for `worker_routes.py` in Phase 01).

## 3. Vulnerability Verification

Per Step 4's explicit instruction, the vulnerability was reproduced with a real test suite **before** any fix was written, not assumed from the audit.

The full regression test file (Section 9) was authored first, encoding the *intended, correct* post-fix behavior, then run against the unmodified `distributed_routes.py`. Result: **10 of 29 tests failed**, all in the exact predicted shape — every Viewer/Analyst request to `retry`, `cancel`, `dead-letter/requeue`, and (see Section 1) `GET /{entry_id}` returned `200`/`200` instead of the expected `403`. Representative failure:

```
FAILED ...TestQueueAuthorizationMutations::test_viewer_cannot_mutate[POST-/api/v1/queue/retry/jq-1]
FAILED ...TestQueueAuthorizationMutations::test_viewer_cannot_mutate[POST-/api/v1/queue/cancel/jq-1]
FAILED ...TestQueueAuthorizationMutations::test_viewer_cannot_mutate[POST-/api/v1/queue/dead-letter/dl-1/requeue]
FAILED ...TestQueueAuthorizationSingleEntryDetail::test_viewer_cannot_read_single_entry_detail[/api/v1/queue/jq-1]
(+ 6 more, Analyst equivalents and a side-channel/authorization-ordering check)
10 failed, 19 passed
```

This is direct, reproducible evidence — not an inference from the audit document. **VERIFIED.**

## 4. Affected Endpoints / Operations

All in `src/kingsec/adapters/inbound/web/distributed_routes.py`, prefix `/api/v1/queue` (the "Workers" execution subsystem's queue — see Section 6 for why this is a distinct system from the similarly-named `queue_routes.py`):

| Method | Path | Operation | Fixed? |
|---|---|---|---|
| POST | `/api/v1/queue/retry/{entry_id}` | Retry a failed job | Yes — now Admin-only |
| POST | `/api/v1/queue/cancel/{entry_id}` | Cancel a job | Yes — now Admin-only |
| POST | `/api/v1/queue/dead-letter/{entry_id}/requeue` | Requeue a dead-lettered job | Yes — now Admin-only |
| GET | `/api/v1/queue/{entry_id}` | Single-entry detail (includes `payload`/`target`) | Yes — now Admin-only (Section 1) |
| GET | `/api/v1/queue` | List all queue entries (no `payload`) | Left open to any authenticated user, deliberately (Section 6) |
| GET | `/api/v1/queue/metrics` | Aggregate queue metrics | Left open, deliberately |
| GET | `/api/v1/queue/dead-letter` | List dead-letter entries (no `payload`) | Left open, deliberately |

**Checked and confirmed NOT affected / not part of this operation graph:**
- `src/kingsec/adapters/inbound/web/queue_routes.py` — a genuinely separate, parallel queue implementation (different domain type `QueueEntry` vs. `JobQueueEntry`, different service `QueueServicePort` vs. `JobQueueRepositoryPort`/`RetryManager`/`DeadLetterService`, different underlying "Agents" execution subsystem vs. "Workers"), coincidentally mounted at the same `/api/v1/queue` URL prefix. Already correctly requires Admin on all of its own mutating endpoints (`_require_admin` present at every relevant call site, verified by reading the full file). Confirmed no path-collision risk: `queue_routes.py` is registered before `distributed_routes.py` in `versioning.py`, and the two routers' literal path shapes don't overlap (`/entry/{id}/cancel` vs. `/cancel/{id}`), so neither router's routes can be reached through the other's registration. Left untouched.
- `src/kingsec/adapters/inbound/web/worker_routes.py` — Phase 01's fix, confirmed intact (Section 14).

## 5. Root Cause

Identical root cause to Phase 01, in a sibling file: `get_current_user` (authentication only) was used where `require_admin`/a role check (authorization) was needed. The existing pattern for exactly this situation already existed in the same codebase — literally in the sibling router at the same URL prefix (`queue_routes.py`'s own `_require_admin` helper) — it simply was never applied in `distributed_routes.py`.

## 6. Authorization Model

Determined from the actual current architecture, not assumed:

- **Role-based, not ownership-based, for this resource type.** `JobQueueEntry` (`src/kingsec/domain/job.py`) has **no owner/user field anywhere in its definition or construction** — confirmed by reading the dataclass and every code path that builds one (`RetryManager`, `DeadLetterService.requeue`, `SQLAlchemyJobQueueRepository`). This queue represents internally-dispatched, worker-execution state (there is no user-facing "create a job" endpoint on this router at all — jobs are dispatched into it by the system, not submitted by users directly), fundamentally unlike `Assessment` (which does carry a real `owner_id` and has real IDOR protection, per the source audit). **Step 5's cross-user ownership testing therefore does not apply to this resource type** — there is no "User A's job" vs. "User B's job" distinction to enforce, because no such distinction exists anywhere in the current domain model. This is a verified conclusion, not an assumption or an omission — documented explicitly rather than silently skipped.
- **The correct policy mirrors the sibling `queue_routes.py` exactly**, which already draws a real, sensible distinction within its own admin-vs-open split: mutating operations require Admin; list/aggregate reads that carry no `payload` are open to any authenticated user; single-entry detail reads that **do** carry `payload`/`target` require Admin (its `get_entry` route). `distributed_routes.py`'s `get_queue_entry` fits the third category exactly (its response includes `payload` and `target`) — this is why it was included in the fix even though the audit's original wording named only the 3 mutations.
- Per Step 2's explicit instruction not to assume every operation needs Admin: `list_queue`, `queue_metrics`, and `list_dead_letter` were deliberately left open to any authenticated user, matching `queue_routes.py`'s own `list_queue`/`get_statistics` precedent for the same shape of "no sensitive payload" data.

## 7. Authorization Matrix

| Operation | Unauthenticated | Viewer | Analyst | Admin |
|---|---|---|---|---|
| List queue (`GET /api/v1/queue`) | 401 | **200** | **200** | 200 |
| Queue metrics (`GET /api/v1/queue/metrics`) | 401 | **200** | **200** | 200 |
| List dead-letter (`GET /api/v1/queue/dead-letter`) | 401 | **200** | **200** | 200 |
| Get single entry detail (`GET /api/v1/queue/{id}`) | 401 | **403** | **403** | 200 |
| Retry job (`POST /api/v1/queue/retry/{id}`) | 401 | **403** | **403** | 200 |
| Cancel job (`POST /api/v1/queue/cancel/{id}`) | 401 | **403** | **403** | 200 |
| Requeue dead-letter (`POST /api/v1/queue/dead-letter/{id}/requeue`) | 401 | **403** | **403** | 200 |

No "Resource Owner" column — not applicable to this resource type (Section 6). All values above are the **actual, live-verified, current behavior**, not the illustrative example table from the prompt (which the prompt itself explicitly said not to blindly copy).

## 8. Fix Implemented

Minimal, adapters-layer-only change in `src/kingsec/adapters/inbound/web/distributed_routes.py` — 18 insertions:

```python
from kingsec.domain import Role
...
ADMIN_ONLY = Role.ADMIN

def _require_admin(user: CurrentUser) -> None:
    if user.role != ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
```

...with `_require_admin(user)` called as the first line of `retry_job`, `cancel_job`, `requeue_dead_letter`, and `get_queue_entry` — before any repository/service lookup in every case, so authorization is enforced before existence is revealed (verified explicitly by a regression test — Section 11). `list_queue`, `queue_metrics`, and `list_dead_letter` were not modified.

This is the **exact same helper-function pattern** already used by the sibling `queue_routes.py` in the same file's URL namespace — no new authorization framework, no new role, no new permission, no ownership-check machinery invented for a resource type that doesn't have an ownership concept. Router-level gating (Phase 01's approach for `worker_routes.py`, where *every* route needed Admin) was deliberately not used here, since this router has a real, legitimate mix of open and admin-only routes — gating the whole router would have over-restricted the 3 endpoints that are correctly open today.

## 9. Regression Tests

New file: `tests/integration/adapters/inbound/web/test_distributed_queue_authorization.py` — **30 tests**, all new. No existing test was modified, weakened, skipped, or deleted (there were none to begin with for this router — Section 2).

Same real-API-boundary pattern as Phase 01 and the codebase's own `test_rbac.py`: a real FastAPI app with the actual `distributed_routes.py` router, real `Login`/`RegisterUser`/`TokenService` wiring producing genuine, verifiable JWTs, and real in-memory implementations of `JobQueueRepositoryPort`/`DeadLetterRepositoryPort` (not mocks of the authorization mechanism itself).

- `TestQueueAuthorizationUnauthenticated` (7 tests) — no credential → 401, all 7 routes.
- `TestQueueAuthorizationMutations` (9 tests) — Viewer/Analyst → 403 on all 3 mutations (6 tests); Admin → 200 on all 3, exercised through the real `RetryManager`/`DeadLetterService` (3 tests).
- `TestQueueAuthorizationSingleEntryDetail` (3 tests) — Viewer/Analyst → 403, Admin → 200 (with real `payload` in the response) on `GET /{entry_id}`.
- `TestQueueAuthorizationOpenReads` (3 tests) — Viewer → 200 on the 3 deliberately-open list/aggregate routes, proving the fix didn't over-restrict.
- `TestQueueAuthorizationBypassAttempts` (7 tests) — Section 11.
- `TestQueueAuthorizationLegitimateWorkflow` (1 test) — Section 10.

## 10. Cross-User Authorization Tests

**Not applicable, verified.** As established in Section 6, `JobQueueEntry` carries no owner/user field anywhere in the domain model or any code path that constructs one — there is no "User A's job" vs. "User B's job" distinction that could exist to test. Rather than fabricate a User-A-vs-User-B test against a resource shape that has no ownership concept, this is documented here explicitly as a **verified negative finding**: cross-user ownership does not apply to this resource type in the current architecture. (Contrast with `Assessment`, which the source audit already confirmed does have real, working IDOR protection based on a genuine `owner_id` field — a materially different resource.)

## 11. Bypass Tests

All exercised through the real HTTP boundary, real JWT verification chain:

- Missing `Authorization` header → 401 (covered by the unauthenticated test class).
- Malformed token string → 401.
- A syntactically-plausible but never-issued ("forged") token → 401.
- A genuinely-issued token with a malformed role claim (not a real `Role` value) → 401 `"invalid token claims"` (fails closed, distinct code path from "valid role, insufficient privilege").
- An unissued/expired-shaped token → 401 (same honest limitation as Phase 01: the stub token service doesn't model real expiry timing — documented in the test's own docstring).
- `GET /{entry_id}` checked explicitly as a potential side-channel around the mutation-level admin gate for a Viewer → still 403.
- **Authorization enforced before resource existence is revealed**: a Viewer targeting a non-existent job ID (`does-not-exist`) still gets **403**, not 404 — proving `_require_admin` runs before the repository lookup in every fixed route (this test's assertion changed from the pre-fix reproduction, where the same request returned 404 with zero auth check ever executing — see Section 3).
- The alternate, lower-level sibling router (`queue_routes.py`) checked directly to confirm it does not offer a Viewer an equivalent unprotected path to the same conceptual operation — confirmed already independently gated (Section 4).

**Not applicable / no meaningful distinct test for this resource type**, stated explicitly per the evidence standard rather than skipped silently: "invalid user ID" and "another user's job ID" bypass categories (Step 9's list) don't have distinct meaning here beyond what's already covered — JWT verification in this codebase's `_verify_jwt()` trusts the token's own role claim directly and does not re-look-up the user repository per request (that lookup only happens for API-key authentication, a separate path not exercised by this fix), and there is no per-job ownership to probe (Section 6/10). Path/query-parameter manipulation is covered by the non-existent-ID test above; there is no query parameter on any of the fixed routes that could alter authorization outcome.

## 12. Full Test Results

**New queue authorization tests alone:**
```
30 passed, 1 warning in 4.09s
```

**New queue tests + Phase 01 worker tests + all other queue/worker/schedule-adjacent existing tests together:**
```
79 passed, 1 warning in 6.19s
```

**Complete backend test suite, after the fix:**
```
2770 passed, 0 failed, 0 skipped, 0 errors, 3 warnings in 144.79s (0:02:24)
```
2770 = the 2,740-test Phase-01-ending baseline + 30 new tests. **No existing test failed**, so none needed investigation for reliance on the vulnerability — the fix is purely additive/restrictive.

**Static validation:**
- `ruff check` on both changed files: clean, zero issues.
- `mypy` on `distributed_routes.py`: clean, zero issues.
- Import-linter (`lint-imports`) architecture-boundary check: **not installed in this environment** (consistent with the source audit's own prior finding) — not installed for this task, per Step 12's "do not introduce a major new toolchain" constraint. Manually confirmed instead: the fix's only new import (`from kingsec.domain import Role`) is an adapters-layer file importing from the domain layer — the same direction already used by the untouched sibling `queue_routes.py` in the same file, and domain is the architecture's innermost layer, always a legal import target from any outer layer.

## 13. Files Changed

| File | Why |
|---|---|
| `src/kingsec/adapters/inbound/web/distributed_routes.py` | The fix: `_require_admin` helper (mirroring `queue_routes.py`) + 4 call sites + 1 import. 18 insertions, 0 deletions — purely additive. |
| `tests/integration/adapters/inbound/web/test_distributed_queue_authorization.py` | New file: 30 regression tests (Section 9). |

No other file was modified. Confirmed via `git diff --stat` and `git status` immediately before writing this report — the only other changes present in the working tree are Phase 01's already-verified, untouched `worker_routes.py` fix and its test file.

## 14. Phase 01 Compatibility

**Confirmed intact.** `worker_routes.py`'s router-level `dependencies=[Depends(require_admin)]` (added in Phase 01) is present and unmodified — verified by direct grep before starting this phase and again by `git diff --stat` after finishing it (zero lines changed in that file this phase). Phase 01's own 32-test suite (`test_worker_routes_authorization.py` + `test_worker.py`) was re-run standalone before starting Phase 02 (32 passed) and again as part of the combined 79-test run above (still all passing) and the full 2,770-test suite. No regression.

## 15. Remaining Phase 02 Issues

None found. All 4 confirmed-vulnerable operations on `distributed_routes.py` (the 3 named by the audit plus the 1 additional single-entry-detail read found by direct comparison against the sibling implementation) are fixed and covered by regression tests. The 3 deliberately-open read routes were verified, not merely assumed, to be correctly left open (matching the sibling's own established, sensible pattern).

## 16. Deferred Audit Findings

All other audit findings remain intentionally untouched because this task is Phase 02 only.

## 17. Phase 03 Recommendation

Do NOT implement Phase 03. Per the source audit's own prioritization, the next highest-value, correctness-and-diagnosability-focused item (not scanner validation, not new features) is: **assessment `failure_reason` not being exposed through the API/DTO** (`AssessmentView.from_domain()` in `application/dto.py` omits the field the domain and database already capture correctly) — a well-localized, evidence-backed defect the source audit already traced to its exact root cause, structurally similar in shape and effort to Phases 01–02 (a small, additive, well-testable fix rather than a redesign).
