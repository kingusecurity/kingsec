# KingSec Phase 01 — Worker Authorization Remediation

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`)
**Scope:** Worker-management authorization only, per `Downloads/new prompt.txt`'s strict scope limit. No other audit finding was touched.

---

## Baseline (Phase 0)

Captured before any change was made:

- Branch: `main`
- Commit: `4f4b666` (`fix(assessment): stop a status-poll race from 404ing right after submit`)
- `git status` before changes: working tree clean except pre-existing, unrelated untracked artifacts (`docs/audits/`, `docker-build-log.txt`, `kingsec-image.tar`, `rebuild-frontend.ps1`, and two stray `*__no_changes.py` files — a known, pre-existing, unrelated test-hygiene bug documented in the source audit, not touched by this task).
- Backend test suite (`pytest`, full run, before any change): **2,718 passed, 0 failed, 0 skipped, 0 errors, 3 warnings, 144.78s.**
- Frontend test suite: not affected by this task (backend-only change) and not re-run for this report; no frontend files were touched.
- Files identified as responsible for the issue: `src/kingsec/adapters/inbound/web/worker_routes.py` (the sole file implementing every worker-management HTTP endpoint — confirmed the only file in the repository that constructs `WorkerRegistrationService`/`HeartbeatManager`).

---

## 1. Original Vulnerability

Every route in `worker_routes.py` depended only on `Depends(get_current_user)` — authentication, not authorization. Any authenticated user of any role, including a brand-new, self-registered, default-role Viewer, could register fake distributed workers, forge heartbeats claiming arbitrary status/health, and delete any real worker by ID. There was no role or permission check anywhere in the file.

Verified directly against the current repository before making any change (Step 1) — this was not assumed from the audit; the file was read in full and every one of its five routes was confirmed to carry only `user: CurrentUser = Depends(get_current_user)`, with no `require_admin`/`require_role`/manual role check anywhere.

## 2. Affected Endpoints

All five routes in `src/kingsec/adapters/inbound/web/worker_routes.py`, prefix `/api/v1/workers`:

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/v1/workers/register` | Register a new worker node |
| POST | `/api/v1/workers/heartbeat` | Report worker status/health/current jobs |
| GET | `/api/v1/workers` | List all workers |
| GET | `/api/v1/workers/{worker_id}` | Get one worker's details |
| DELETE | `/api/v1/workers/{worker_id}` | Delete a worker |

**Endpoints checked and confirmed NOT affected / out of scope:**
- `src/kingsec/adapters/inbound/web/agent_routes.py` (`/api/v1/agents/*`) — a genuinely separate, sibling subsystem (distinct domain concept `Agent`, distinct service `AgentServicePort`). Every one of its mutating routes (register, heartbeat, disable, enable, delete, job assignment/progress/complete/fail) already correctly calls a local `_require_admin(user)` helper. This file already implements the intended pattern correctly and was left untouched.
- `src/kingsec/adapters/inbound/web/dashboard_routes.py`'s `GET /workers` — a read-only aggregate statistics endpoint (uptime/jobs-completed counts), not part of the `WorkerRegistrationService`/`HeartbeatManager` worker-management surface, cannot mutate anything. Confirmed via grep that `worker_routes.py` is the only file in the repository that constructs `WorkerRegistrationService` or `HeartbeatManager`. Left untouched as out of scope.

## 3. Root Cause

The route handlers were written using `get_current_user` (which only verifies *who* the caller is) where `require_admin`/`require_role(...)` (which additionally verifies the caller has sufficient *privilege*) was needed. This is a straightforward "authentication used where authorization was required" omission — the existing RBAC machinery (`Role` enum, `require_role()`, pre-built `require_admin`) already existed and is used correctly elsewhere in the same codebase (e.g. `secret_routes.py`, `agent_routes.py`); it simply was never applied here.

## 4. Fix Implemented

One-line, router-level change in `src/kingsec/adapters/inbound/web/worker_routes.py`:

```python
from .auth import CurrentUser, get_current_user, require_admin
...
router = APIRouter(prefix="/api/v1/workers", tags=["workers"], dependencies=[Depends(require_admin)])
```

This reuses the codebase's **existing** RBAC system exactly as-is — no new authorization framework, no new role, no new permission was created. `require_admin` is a pre-built alias (`require_role(Role.ADMIN)`) already used identically by `secret_routes.py` for its own admin-only router. Gating at the **router level** (rather than per-route) means every route under this prefix is protected by construction, including any route added to this file in the future — there is no per-route check to accidentally omit.

The per-route `user: CurrentUser = Depends(get_current_user)` parameters were deliberately left in place (not removed) — they are harmless (FastAPI resolves the dependency once, cached), and removing them was unrelated cleanup outside this task's scope.

**Why the whole router, including the two GET routes:** worker administration is internal distributed-scanning infrastructure management, not user-facing product data — there is no legitimate reason for a non-admin Viewer or Analyst to need visibility into it, and gating the entire router is both the simplest correct fix and consistent with the only other precedent in this codebase for this exact kind of subsystem (`secret_routes.py`).

## 5. Authorization Matrix

| Actor | Expected | Actual |
|---|---|---|
| Unauthenticated | 401 | **401** — confirmed for all 5 endpoints |
| Viewer | 403 | **403** — confirmed for all 5 endpoints |
| Analyst | 403 | **403** — confirmed for all 5 endpoints |
| Admin (privileged role) | Success | **Success** — confirmed via a real register → list → get → heartbeat → delete lifecycle |

## 6. Regression Tests

New file: `tests/integration/adapters/inbound/web/test_worker_routes_authorization.py` (22 tests, all new — no existing test was modified, weakened, skipped, or deleted).

Built on the same real-API-boundary pattern already established in this codebase's `tests/integration/adapters/inbound/web/test_rbac.py` (reused its `StubTokenService`/`StubUserRepo`/`StubHasher`/`_register_user`/`_register_viewer`/`_promote_user_in_repo`/`_login` helpers directly via import, rather than a `dependency_overrides` shortcut that would bypass the real dependency chain). A real FastAPI app is built with the actual `worker_routes.py` router included; real registration and login produce a genuine, verifiable JWT; the real `require_admin` → `require_role` → `_verify_jwt` chain executes for every request.

- **`TestWorkerAuthorizationUnauthenticated`** (5 tests, parametrized across all 5 endpoints) — no credential → 401.
- **`TestWorkerAuthorizationViewer`** (5 tests) — a real, self-registered default-role Viewer → 403 on every endpoint.
- **`TestWorkerAuthorizationAnalyst`** (5 tests) — a real Analyst (promoted via the same repo helper `test_rbac.py` already uses) → 403 on every endpoint.
- **`TestWorkerAuthorizationAdmin`** (1 test) — a real Admin exercises the full register → list → get → heartbeat → delete lifecycle end-to-end, confirming the fix does not break legitimate use.
- **`TestWorkerAuthorizationBypassAttempts`** (6 tests, Step 6):
  - Missing `Authorization` header → 401 (not 500).
  - Malformed token string → 401.
  - A syntactically-plausible but never-issued ("forged") token → 401 — proves verification is against the real issued-token store, not just decoding an unverified shape.
  - `GET /workers/{id}` (the narrower single-resource route) checked explicitly as a potential side-channel around the router-level gate for a Viewer → still 403.
  - An unissued/expired-shaped token → 401 (the stub token service doesn't model real expiry timing, so this exercises the same "token not found in issuer's store" path a real expired-and-purged token would take — documented honestly in the test's own docstring rather than overclaiming full expiry-clock coverage).
  - A genuinely-issued, genuinely-verified token carrying a **malformed role claim** (`"not-a-real-role"`, not a real `Role` value) → 401 `"invalid token claims"` — a distinct code path from "valid role, insufficient privilege," proving the system fails closed rather than defaulting to any implicit privilege level.

**Alternate HTTP methods / alternate routes**, the remaining Step 6 items: addressed architecturally rather than by an additional test — because the fix is a **router-level** dependency, every method on every path under `/api/v1/workers` is protected by construction; there is no route-specific check that a new or unanticipated method/path could bypass. Confirmed no other route file in the repository touches the same worker services (see Section 2).

**Vulnerability reproduction (proof the tests actually test something):** before finalizing, a standalone, read-only scratch script (outside the test suite and outside any tracked file — `git status` confirms it was never part of the repository) reconstructed the exact pre-fix router shape using the real, unmodified route-handler functions imported from `worker_routes.py`, with no admin dependency attached, and confirmed a real Viewer-role JWT reaches `GET /api/v1/workers` with **HTTP 200** in that shape — versus **HTTP 403** from the actual, fixed router in the real test suite for the identical request. This confirms the new tests exercise the real vulnerability, not a coincidental pass.

## 7. Test Results

**New + existing worker tests together** (`tests/unit/application/test_worker.py` + the new file):
```
32 passed, 1 warning in 3.45s
```

**Complete backend test suite**, after the fix:
```
2740 passed, 0 failed, 0 skipped, 0 errors, 3 warnings in 154.55s (0:02:34)
```

2740 = the 2,718-test baseline + the 22 new tests. **No existing test failed, so none needed to be examined for reliance on the vulnerability** — the fix is purely additive/restrictive and broke nothing already passing.

`ruff check` and `mypy` on both changed files: clean, zero issues.

## 8. Files Changed

| File | Why |
|---|---|
| `src/kingsec/adapters/inbound/web/worker_routes.py` | The fix: added `require_admin` router-level dependency (import + one line + explanatory comment). 7 insertions, 2 deletions — the entire diff. |
| `tests/integration/adapters/inbound/web/test_worker_routes_authorization.py` | New file: 22 regression tests proving the fix (Section 6). |

No other file in the repository was modified. Confirmed via `git diff --stat` and `git status` immediately before writing this report.

## 9. Security Verification

- Confirmed the vulnerability existed in the current code by direct inspection before changing anything (Step 1), not by trusting the audit document.
- Confirmed no sibling worker-management surface shared the same gap (`agent_routes.py` already does this correctly; `dashboard_routes.py`'s worker statistics endpoint is read-only and touches unrelated services).
- Confirmed the fix fails closed: unauthenticated, Viewer, and Analyst are all rejected (401/403 respectively) across all 5 endpoints, tested through the real HTTP boundary with real JWTs, not a mocked-away authorization function.
- Confirmed the fix cannot be sidestepped via a missing header, a malformed token, a forged/unissued token, a malformed role claim, or the narrower single-resource GET route as a side channel — 6 explicit bypass tests, all passing.
- Confirmed the fix is architecturally bypass-resistant to alternate HTTP methods/routes by construction (router-level dependency, not per-route).
- Confirmed the fix does not regress legitimate access: a real Admin completes the full worker lifecycle (register/list/get/heartbeat/delete) successfully.
- Confirmed via a standalone, non-destructive scratch reproduction that the pre-fix router shape genuinely permitted the exact request the fix now blocks (200 → 403 for the identical Viewer request).
- Confirmed zero regressions across the complete 2,740-test backend suite.

## 10. Remaining Issues

Other audit findings remain intentionally untouched because this task is Phase 01 only.

---

## Report Path

`docs/audits/KINGSEC-PHASE-01-WORKER-AUTHORIZATION-REPORT.md`
