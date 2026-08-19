# KingSec Phase 05 — Scanner Failure Integrity: Design Decision

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`) — unchanged since Phase 01–04; all four remain uncommitted in the working tree.
**Scope:** Design decision only. No source file was changed. No test file was changed. No fix was implemented, per `Downloads/KINGSEC-PHASE-05-PROMPT.md` §0.

---

## 1. Baseline and Phase 01–04 Integrity Check

- Branch: `main`. Commit: `4f4b666`.
- Phase 01–04 markers re-verified directly against current code:
  - `worker_routes.py`: `dependencies=[Depends(require_admin)]` present.
  - `distributed_routes.py`: `_require_admin(user)` present at all 4 call sites.
  - `dto.py` / `schemas.py` / `routes.py`: `failure_reason` present in `AssessmentView`, `AssessmentResponse`, and the route handler.
  - `_support.py`: `safe_failure_message()` present, applied at both `.fail()` call sites.
- Full backend suite before this phase: **2,792 passed, 0 failed, 0 errors, 0 skipped** (JUnit XML, 127.5s).
- **End-of-phase re-check:** `git status` shows the identical modified/untracked file list as at the start of this phase (8 modified source files, 6 untracked test files — all from Phases 01–03). Full suite re-run at the close of this phase: see the closing note in Section 9 for the exact final count; confirmed unchanged from the start-of-phase baseline.
- **Operational risk restated, as required:** Phases 01, 02, and 03's fixes remain uncommitted in the working tree. This has now been true for **five** consecutive phases (01 through 05). Nothing in this repository's git history reflects any of this remediation programme's work yet.

**VERIFIED.**

---

## 2. Re-Verification of the Three [VERIFY] Items

All three re-checked directly against current source, not recalled from the Phase 04 report:

1. **`assessment.complete()` is unconditional at `submit_assessment.py:284` and `start_assessment.py:112`.** Re-confirmed: grepping `submit_assessment.py` for `assessment.complete()` returns exactly one hit, at line 284, immediately after `assessment.record_scanner_summary(ran_summaries + preplanned_skips)` at line 282, with no conditional between them. `start_assessment.py` similarly has exactly one `assessment.complete()`, at line 112, inside a bare `try` block with no findings-count or scanner-outcome check preceding it. **CONFIRMED.**
2. **Zero-findings is not an input to the status decision anywhere.** Re-confirmed: every use of the word `findings` in `submit_assessment.py` was enumerated — `findings` is only used to (a) build the list passed to `assessment.record_finding()`, (b) build an event message string (`f"Scan completed with {len(assessment.findings)} findings"`, line 296), and (c) build severity counts. None of these gate `.complete()` vs. `.fail()`. **CONFIRMED.**
3. **`StartAssessment` has no execution engine and never records `scanner_summary`.** Re-confirmed: `StartAssessment.__init__` (`start_assessment.py:45-53`) takes no `execution_engine` parameter at all, and a grep for `execution_engine|scanner_summary` across the entire file returns zero matches outside the single `assessment.complete()` line itself. **CONFIRMED.**

All three Phase 04 findings hold exactly as stated. No misread found.

---

## 3. Exhaustive `ScannerPort` / `ScannerExecutor` Implementation and Test-Double Inventory

Settling Phase 04 §9's explicit UNKNOWN. Method: grep for every literal `class X(ScannerPort)` / `class X(ScannerExecutor)` / `class X(ScannerPort, ScannerExecutor)` declaration across the entire repository (`src/` and `tests/`), then a second pass for structurally-conforming test doubles that implement both `scan()` and `compatible_scanners()` without literally subclassing the ABC (Python does not enforce this at call sites — a use case typed to accept `ScannerPort` will happily accept any duck-typed object).

### `ScannerPort` implementations — 9 production, 1 production/dual, 10 test doubles = **20 total**

| # | Class | Location | Kind |
|---|---|---|---|
| 1 | `NmapScannerAdapter` | `nmap.py:27` | Production adapter |
| 2 | `NucleiScannerAdapter` | `nuclei.py:28` | Production adapter |
| 3 | `NiktoScannerAdapter` | `nikto.py:28` | Production adapter |
| 4 | `FfufScannerAdapter` | `ffuf.py:27` | Production adapter |
| 5 | `GobusterScannerAdapter` | `gobuster.py:27` | Production adapter |
| 6 | `AmassScannerAdapter` | `amass.py:27` | Production adapter |
| 7 | `TrivyScannerAdapter` | `trivy.py:27` | Production adapter |
| 8 | `ZapScannerAdapter` | `zap.py:27` | Production adapter |
| 9 | `SemgrepScannerAdapter` | `semgrep.py:27` | Production adapter |
| 10 | `ScannerOrchestrator` | `orchestrator.py:35` | Production, **also** implements `ScannerExecutor` — the only class bound to `ScannerPort` in `composition.py`/`provisioning.py` (`provisioning.py:90: register(ScannerPort, orchestrator)` — the single, exclusive binding) |
| 11 | `_StubScanner` | `tests/integration/bootstrap/test_composition.py:61` | Test double, explicit subclass |
| 12 | `_StubScanner` | `tests/integration/ai/test_ai_integration.py:83` | Test double, explicit subclass |
| 13 | `_StubScanner` | `tests/integration/reporting/test_reporting_integration.py:58` | Test double, explicit subclass |
| 14 | `_StubScanner` | `tests/integration/persistence/test_wiring_and_slice.py:34` | Test double, explicit subclass |
| 15 | `_StubScanner` | `tests/integration/adapters/inbound/web/test_web_integration.py:47` | Test double, explicit subclass |
| 16 | `StubScanner` | `tests/unit/application/conftest.py:144` | Test double, explicit subclass — shared fixture used across most of `tests/unit/application/*` |
| 17 | `FakeScanner` | `tests/unit/application/test_submit_assessment.py:57` | Test double, duck-typed (not a literal subclass; conforms structurally) |
| 18 | `RecordingScanner` | `tests/unit/application/test_submit_assessment.py:98` | Test double, duck-typed |
| 19 | `_RecordingScanner` | `tests/unit/application/test_start_assessment.py:42` | Test double, duck-typed |
| 20 | `_RaisingScanner` | `tests/unit/application/test_assessment_failure_sanitization.py` | Test double, duck-typed (this investigation's own Phase 03 addition) |

### `ScannerExecutor` implementations — **1 real, 1 deliberately-incomplete non-double**

| Class | Location | Kind |
|---|---|---|
| `ScannerOrchestrator` | `orchestrator.py:35` (same class as row 10 above) | The **only** real `ScannerExecutor` implementation in the entire repository. |
| `PartialExecutor` | `tests/unit/application/test_scanner_ports.py:251` | Deliberately missing `execute_all()`; the test (`test_incomplete_implementation_cannot_instantiate`) asserts it **cannot be instantiated** (`TypeError`). Not a usable double — excluded from the count above. |

**Composition-root bindings — exactly 1.** `provisioning.py:90` is the sole `register(ScannerPort, orchestrator)` call in the entire codebase; `composition.py:563-564`'s `_resolve_scanner_executor()` does not add a second binding — it re-resolves the same `ScannerPort` registration and checks `isinstance(scanner, ScannerExecutor)`, which is `True` only because `ScannerOrchestrator` happens to implement both.

**Test methods in the 22 files whose fixtures directly touch `ScannerPort`/`ScannerExecutor`/the two assessment use cases:** counted directly (`grep -c "def test_"` per file, summed): **341 test methods** across `test_{nmap,nuclei,nikto,ffuf,gobuster,amass,trivy,zap,semgrep}_plugin.py` (9 files), `test_adapter.py`, `test_orchestrator.py`, `test_scanner_ports.py`, `test_start_assessment.py`, `test_submit_assessment.py`, `test_get_and_report.py`, `test_assessment_failure_sanitization.py`, `test_nuclei_integration.py`, `test_composition.py`, `test_ai_integration.py`, `test_reporting_integration.py`, `test_wiring_and_slice.py`, `test_web_integration.py`. This is an honest upper bound on the at-risk surface, not a precise breakage count — a change scoped only to `ScannerExecutor.execute_all()`'s return shape (rather than `ScannerPort.scan()` itself) would put far fewer of these 341 at real risk, since most exercise `scan()`/adapter-level behavior that a narrower change would not touch. **Labeled: real count of touched files and gross test-method exposure; not a precise per-test breakage prediction, which depends on which exact contract shape is chosen.**

**VERIFIED**, real counts, not estimates.

---

## 4. Option A vs. Option B — Evaluation and Decision

### A nuance Phase 04 did not separate: "Option B" is actually two different-sized changes

- **B1 — narrow: change only `ScannerExecutor.execute_all()`'s return shape** (e.g., have it return both successes and structured failures instead of silently omitting failed plugins from the tuple). Blast radius: `scanner_executor.py` (port), `orchestrator.py` (the only implementation), `submit_assessment.py` (the only caller that ever uses `scanner_executor`, and only when it happens to be non-`None`). **This variant does not close the gap for `StartAssessment`** — that use case never references `ScannerExecutor` at all (Section 2, item 3), so B1 leaves it exactly as blind as it is today. Functionally, B1 is close to a more invasive version of Option A: it still requires `SubmitAssessment` to consult the richer data before completing, just packaged differently.
- **B2 — the shape the prompt's wording actually describes ("so any caller can decide correctly"): change `ScannerPort.scan()` itself** to return a structured outcome instead of a bare `Sequence[Finding]`. This is the only version of Option B that genuinely closes the gap on both use-case paths with one mechanism, because `StartAssessment` only ever calls `scan()`. Blast radius, counted from Section 3's inventory: the port definition (1 file), all 9 production adapters whose `scan()` return type/logic would change (9 files), `ScannerOrchestrator.scan()`'s flattening logic (already counted in `orchestrator.py`, same file as its `ScannerExecutor` role), both use cases (`start_assessment.py`, `submit_assessment.py` — 2 files), and every one of the 9 distinct test files containing the 10 `ScannerPort` test doubles from Section 3 (since all 10 doubles currently return a bare findings sequence and would need to conform to the new shape). **Total: at least 1 + 9 + 2 + 9 = 21 files with a certain, direct edit**, before counting how many of the 341 test methods in those files need their assertions updated to match the new return shape. This is larger than Phase 04's original 8–15 estimate, now that it is counted rather than guessed.

### Evaluated against the four criteria

| Criterion | Option A | Option B1 | Option B2 |
|---|---|---|---|
| Closes gap on both paths with one mechanism? | No — by design, needs a second, separate step for `StartAssessment` | No — same limitation as A, worse (bigger diff for the same non-result) | Yes — the only option that does |
| Blast radius (measured) | 1–2 files (`submit_assessment.py`, optionally `start_assessment.py` if wired up) | 3 files | ≥21 files, 341 test methods in the at-risk zone |
| Regression risk vs. 2,792-test baseline | Low — additive conditional in one function | Low-moderate — changes one port's return shape, consumed in one place | High — a public port contract change rippling through 9 adapters and 10 test doubles simultaneously |
| Leaves codebase easier to fix *next* time this bug class appears | Partially — the pattern (check `scanner_summary` before finalizing) is now established, but `StartAssessment` still needs its own version of it if ever revived | Barely better than A for this purpose | Yes — a structurally impossible-to-forget contract (the caller cannot get a bare findings list without also getting failure info) |

### Decision: **staged path — Option A now, Option B2 later, with a concrete trigger**

**Reasoning:** Section 6 (§2.4 below) establishes that `StartAssessment` is not reachable from any production entry point today — it is dead code from a reachability standpoint, resolvable to Option 3 of §2.4 (accept and document, not fix) rather than something Phase 06 needs to wire up. This removes B2's single decisive advantage over A for *today's* codebase: **A closes the gap on the only path that is actually live**, at a small fraction of B2's blast radius and regression risk. Choosing B2 now would mean touching 21+ files and 341 at-risk test methods to unify behavior across a live path and a dead one — paying B2's full cost for a benefit (`StartAssessment` correctness) that has no current user.

B2 is not rejected outright — it is deferred, with an explicit, concrete trigger: **the day `StartAssessment` (or any future synchronous scan path) becomes reachable from a live entry point again, Option A's fix must either be duplicated onto that path or Option B2 must be implemented at that time** — do not let a revived `StartAssessment` route ship without one or the other; that is exactly how this defect existed in the first place (an existing, only-sometimes-consulted mechanism, `AssessmentExecutionEngine`, that a second call path silently never adopted).

**VERIFIED / JUDGEMENT.** The blast-radius and reachability findings are verified counts and a verified trace; the choice of A-now/B2-later is a judgement call, reasoned above, not a fact to be re-derived.

---

## 5. Partial-Failure Policy

**The sufficiency question, argued both ways, before the conclusion:**

**For sufficiency of `COMPLETED` + accurate `scanner_summary` alone:** Phase 04 §5 (re-confirmed unchanged in Section 2 above) proved the report layer already renders per-scanner outcome correctly today, with zero further plumbing. `scanner_summary` is already present on `AssessmentResponse` (a Phase-03-era, already-shipped field). A `COMPLETED` assessment that genuinely produced some real, actionable findings should not be relabeled in a way that makes those findings look untrustworthy or hides them behind an alarming top-level status a triage workflow might deprioritize or route differently. Reusing `COMPLETED` is also zero-migration, zero-new-domain-transition-method, and — concretely, per Section 6 below — avoids reopening the `Report.from_assessment()` gate at `report.py:228` (`if assessment.status is not AssessmentStatus.COMPLETED: raise IllegalStateTransition`), which today would flatly refuse to generate a report for anything but `COMPLETED`.

**Against sufficiency:** Phase 04 §6's live proof (script 3) showed the *exact same HTTP response* already carries both the reassuring `status: "completed"` and the damning `scanner_summary: [{"status": "failed", ...}]` — and no existing UI affordance (Phase 03 §10, re-confirmed not rebuilt since) surfaces `scanner_summary` at all; every affordance surfaces `status` prominently. "The data is there" is not the same as "the user will see it." A silent `COMPLETED` with zero findings, where the zero came from every scanner failing rather than genuine cleanliness, is indistinguishable at the only layer a real user actually looks at — this is precisely the finding this whole four-phase investigation exists to fix, and leaving it purely at "the data is technically present" would not fix it.

**Conclusion: `COMPLETED` + `scanner_summary` is *data-sufficient* but not *signal-sufficient*.** The status field itself does not need to change for the partial case (see Section 6 — `PARTIAL` is rejected as a *status*), but the response needs an additional, cheap, top-level signal a UI can key a warning off of without parsing `scanner_summary` — see the recommendation in Section 10. This is a *direction*, not a full design, per §0's prohibition on this phase deciding implementation shape.

### Policy table

| Scanners attempted | Outcome | Intended status | Intended `failure_reason` | Reasoning |
|---|---|---|---|---|
| All succeeded | findings > 0 | `COMPLETED` | `null` | Unambiguous; matches current, correct behavior. No change. |
| All succeeded | zero findings | `COMPLETED` | `null` | Unambiguous; genuinely clean. No change. |
| All failed | — | `FAILED` | Non-null — a scanner-name-based summary (Section 8), not raw exception text | Phase 04 §6 proved this is the most damaging case today (silently `COMPLETED`). Unambiguous: no scanner produced any real signal, so there is nothing to preserve by staying `COMPLETED`; `FAILED` is the honest state and matches the existing domain vocabulary exactly (no new state needed for this row). |
| Some failed, some succeeded | findings > 0 | `COMPLETED` | `null` (domain constraint — see Section 6) | Real findings exist and must not be hidden behind a `FAILED` label or made unreportable. Coverage gap is real but the assessment is not wholly untrustworthy. Needs the advisory signal noted above (design direction, not decided here) so the gap is not silent. |
| Some failed, some succeeded | zero findings | `COMPLETED` | `null` (domain constraint — see Section 6) | The hardest row, and the one likeliest to be misread as "confirmed clean" — it is not: the zero could be masking exactly what a failed scanner would have found. Same status as the row above for consistency and to avoid a fourth special case, but this is the row where the advisory signal matters *most* — flagged explicitly as the highest-priority case for whatever Phase 06 designs. |
| All pre-planned skips, none ran | — | `COMPLETED` | `null` | Already correctly distinguished today: `preplanned_skips` (from the profile planner, e.g. an incompatible target type or explicit profile exclusion) is a deliberate plan, not an execution failure — `scanner_summary` already renders these with their real `skipped_reason`, verified in Phase 04 §5. No policy change needed; explicitly not conflated with the "attempted and failed" rows above. |

**JUDGEMENT**, reasoned above; the two middle rows are the ones this phase exists to settle deliberately rather than by accident, per the prompt's own framing.

---

## 6. `PARTIAL` Domain State — Rejected

**Decision: rejected.** `AssessmentStatus` remains `DRAFT | AUTHORIZED | RUNNING | COMPLETED | CANCELLED | FAILED` — no new member is added.

**Full impact inventory, produced before rejecting (not skipped):**

- **Every location that pattern-matches on `AssessmentStatus`:** a precise grep for the literal enum-member-reference pattern `AssessmentStatus\.` across `src/` returns exactly 3 files: `domain/enums.py` (the enum's own definition, including its `is_terminal` property at `enums.py:43-50`), `domain/assessment.py` (the `_ALLOWED_ASSESSMENT_TRANSITIONS` table and its `_transition_to()` guard), and `domain/report.py` (the `COMPLETED`-only gate, cited below). Everywhere else in the codebase (`dto.py`, `schemas.py`, `routes.py`, the ORM, the mappers) treats status as an opaque string, so adding a member does not itself break those call sites structurally — the exposure is narrower than "every consumer of assessment status," but the 3 files it does touch are the domain's own core invariants, not incidental call sites.
- **A new domain state requires more than an enum member.** `Assessment` has exactly three status-mutating methods today: `.complete()`, `.fail(reason)`, `.cancel()` (`assessment.py:255-269`), each calling `._transition_to()` with a specific target. A `PARTIAL` outcome cannot reuse `.complete()` (it currently sets no failure-adjacent data) or `.fail()` (which structurally requires ending in `FAILED` and requires a non-empty `reason`, per `fail()`'s own validation at `assessment.py:259-265`). It would need a **new mutator method** and a **new entry in `_ALLOWED_ASSESSMENT_TRANSITIONS`** (`RUNNING -> {COMPLETED, FAILED, CANCELLED, PARTIAL}`), not just a bigger enum.
- **Persisted status column / migration:** `AssessmentORM.status` (confirmed in Phase 03's investigation) is a free-text column keyed by `AssessmentStatus[orm.status]` on read — no CHECK constraint or DB-level enum type was found, so a new member does not itself require an Alembic migration for the column's shape. Existing rows need no backfill (nothing pre-`PARTIAL` would ever have this value). **This part is cheap** — it is the domain-method and gate work above, and the frontend/report work below, that carry the real cost.
- **Terminality:** would need to be `True` in `AssessmentStatus.is_terminal` (matching `COMPLETED`/`CANCELLED`/`FAILED`'s existing membership) — a partial run does not resume.
- **Report generation interaction — a concrete, found blocker:** `domain/report.py:225-232`'s `Report.from_assessment()` explicitly gates on `assessment.status is not AssessmentStatus.COMPLETED` and raises `IllegalStateTransition` otherwise. A `PARTIAL` assessment would be **refused a report today**, which directly contradicts the reasoning in Section 5 for why the partial-with-real-findings case must stay reportable. Adopting `PARTIAL` would require deliberately widening this gate to accept `PARTIAL` too — a domain-rule change with its own review burden, not a side effect that happens for free.
- **Frontend impact — compounds existing unbuilt work, not just adds to it.** Phase 03 §10 (re-confirmed, not rebuilt since) already found `AssessmentDetailPage.tsx` computes `isRunning`/`isPending`/`isDraft`/`isCompleted` but has **no `isFailed` branch at all** — the simpler, already-decided `FAILED`-visibility work from Phase 03 is itself still unbuilt. Introducing `PARTIAL` as a third terminal state needing its own frontend branch, before the second one (`FAILED`) has even been built, means Phase 06+ would owe the frontend two new branches instead of one, on top of the `failure_reason: string | null` TS type field Phase 03 §10 already identified as missing.

**Reasoning for rejection:** every one of the four dimensions §2.3 asks to inventory (pattern-match sites, migration, terminality/report interaction, frontend cost) carries real, non-trivial cost, and Section 5 already established that the *data* (`scanner_summary`) is not what's missing — visibility of it is. A new terminal status solves a problem (distinguishing partial from clean *in the data model*) that Phase 04 §5 already proved is solved; it does not solve the actual problem (distinguishing partial from clean *to the user looking at the product*), which is a rendering/signal problem, not a taxonomy problem. Recorded here as a rejection so it is not silently reopened later without new evidence, per the prompt's own instruction.

**VERIFIED** (impact inventory) **/ JUDGEMENT** (the rejection itself, reasoned above).

---

## 7. `StartAssessment` Reachability — Finding and Resolution

**Traced exhaustively, per §2.4's explicit instruction, across `composition.py`, every route handler, and `service_api.py`:**

- `composition.py:574-583` registers `StartAssessment` in the DI container and wires it with a real `AssessmentRepository`/`ScannerPort`/etc. — it is **constructible**, not literally removed code.
- `service_api.py:66-67`: `UseCaseServiceAPI.start_assessment(request)` delegates to `self._start.execute(request)` — the `ServiceAPI` port **does** expose a method backed by the real `StartAssessment` use case.
- **`src/kingsec/adapters/inbound/web/routes.py`** — the sole inbound HTTP surface in this codebase (`find src/kingsec/adapters/inbound -maxdepth 1 -type d` returns exactly `web`; no CLI, gRPC, or other inbound adapter directory exists) — has exactly one route associated with beginning a scan: `POST /assessments/{assessment_id}/start` (`routes.py:413-447`). Its handler, named `start_assessment` for the route's own labeling, **constructs a `SubmitAssessmentRequest` and calls `service.submit_assessment(request)`** (`routes.py:434-442`) — not `service.start_assessment(...)`. The route's own docstring even says so: `"Submit an authorized assessment for background scanning. Returns 202 Accepted."`
- A grep for `service.start_assessment` / `.start_assessment(` as a *call* (not a definition) across all of `src/` returns **zero matches**. A grep for the string `start_assessment` anywhere in `src/` returns exactly 4 files — `routes.py` (only the route's own name, not a call to the method), `application/__init__.py` (a type re-export), `service_api.py` (the method's own definition), and `ports/inbound/service_api.py` (the abstract method's own declaration). No fifth file calls it.

**Finding: `StartAssessment` is not reachable from any production entry point.** It is fully wired, fully functional, and covered by its own unit tests (`test_start_assessment.py`, 8 test methods) and one integration test (`test_nuclei_integration.py`'s `TestEndToEndSlice`) — but no HTTP route, no CLI, no scheduled job, and no other inbound adapter ever invokes `ServiceAPI.start_assessment()`. It is exercised only by tests calling the use case directly, never through any path a real request could take.

**Resolution chosen: Option 3 — accept it as permanently blind, and document that as an intentional limitation**, with a caveat. Since it is not reachable at all, "permanently blind to this specific defect" is not the operative risk — the operative fact is that it is **unreachable, full stop**, which supersedes the failure-visibility question entirely for the current codebase. It does not need Section 4's Option A wiring, because no real request can ever exercise the code path that would need it.

**The caveat, and why it is not "dead code, delete it":** §0 of this prompt and every prior phase's scope discipline prohibit deleting anything ("If it is dead or wrong, report it; do not remove it" — Phase 04 §0, restated as this program's standing rule). It is reported here, not removed. Whether to delete it, keep it as a documented-unused synchronous alternative, or revive it behind a new route is a product decision outside this phase's scope — flagged as an open question in Section 11.

**This finding materially shrinks Phase 06's scope**, exactly as the prompt anticipated: Phase 06 does not need to design or implement any `StartAssessment`-side fix at all. Combined with Section 4's decision, Phase 06's implementation surface for the actual, live defect is entirely within `submit_assessment.py` (plus the message-composition helper in Section 8 and its regression tests).

**VERIFIED.**

---

## 8. Failure Message Design and the Unsanitized `fail_scanner` Finding

### Message content design (direction, not full implementation — no code is written in this phase)

- **9 of 9 fail:** the message should name every failed scanner (by display name, not raw error text) and state plainly that no scanner completed — e.g. in shape (not final copy): *"All N configured scanners failed to run: Nuclei, Nmap, ... . No results are available for this assessment."* This is the row already decided as `FAILED` in Section 5's table.
- **1 of 9 (or K of N) fail, assessment stays `COMPLETED`:** per Section 5, `failure_reason` stays `null` by domain constraint (it is coupled to the `FAILED` transition — see Section 6). Whatever advisory signal Phase 06 designs for the partial case (Section 5's open direction) should similarly be **scanner-name-and-count based**, e.g. *"1 of 9 configured scanners did not complete: Nikto. Results may be incomplete."* — never raw exception text.
- **In both cases, never interpolate a scanner's raw error string directly into a user-facing message.** This is not a new principle — it is Phase 03's own `safe_failure_message()` design, applied consistently to a new sink.

### The unsanitized `engine.fail_scanner()` finding — confirmed, with severity

Phase 04 §3 flagged that `orchestrator.py:135` calls `engine.fail_scanner(tid, plugin_id.value, str(exc))` with a **raw, unsanitized exception string** — different from and independent of Phase 03's `safe_failure_message()` fix, which only touched the two `assessment.fail(...)` call sites in `start_assessment.py`/`submit_assessment.py`, not this one. This investigation traced where that raw string goes:

1. `AssessmentExecutionEngine.fail_scanner()` (`assessment_execution.py:251-263`) stores it verbatim into `ScannerProgress.error: str | None` (`assessment_execution.py:52`) — no sanitization at this layer either.
2. **`src/kingsec/adapters/inbound/web/execution_routes.py:53-65`**, `_scanner_progress_to_dict()`, includes `"error": sp.error` — the raw string — directly in its output.
3. That function is used by `GET /assessments/{id}/execution/status` (`execution_routes.py:81-112`), which returns `"scanner_progress": [_scanner_progress_to_dict(sp) for sp in state.scanner_progress]` in its JSON body verbatim, at line 108.

**Confirmed: this is a live information disclosure that predates this phase, exactly as the prompt anticipated.** The raw string that reaches this endpoint originates from `orchestrator.py:69-71`'s `f"unexpected error in plugin {id!r}: {exc}"`, where the inner `exc` can be any exception an adapter or the subprocess layer raised — including, per Phase 04 §6's live proof, real OS/subprocess-level error text, and in the general case (per the same reasoning Phase 03 applied to the two `.fail()` sites) potentially absolute paths, internal hostnames, or command-line fragments from an unvetted, lower-level exception.

**Severity: Low–Medium, reasoned explicitly.** This is bounded, not open: `execution_routes.py:36-50`'s `_check_owns_assessment()` gates every route in this file behind the same ownership-or-admin check used everywhere else (`check_assessment_access`) — re-confirmed by reading the function. So this is **not** a cross-user or unauthenticated leak; it discloses internal diagnostic detail only to the assessment's own owner or an admin, i.e., someone already entitled to know their own scan failed. That materially reduces severity relative to Phase 03's original two-sink finding (which had the same underlying root cause but a broader potential audience before Phase 03's fix). It remains a real defect — a security product's own stated design principle (`shared/errors/base.py`'s docstring: "Never leak internals... that is reconnaissance for an attacker") is violated for an authenticated user who could, in principle, be a scan operator without legitimate need to see raw subprocess internals — and it is **live and reachable today** for any assessment run through `SubmitAssessment` (the only live path, per Section 7), whenever a scanner plugin fails.

**Not fixed here, per this phase's own scope and the prompt's explicit instruction to report, not fix.** Recorded as a Phase 06 candidate (Section 10).

**VERIFIED.**

---

## 9. Diagnostic Scripts

None were needed this phase. Every claim in Sections 3, 4, 6, and 7 was settled by direct, exhaustive static grep/read against current source — re-running the live-proof scripts from Phase 04 would have re-demonstrated already-settled facts (Section 2) rather than tested a new design assumption, so none were written, per §0's "may write" (not "must write") framing.

**Closing integrity re-check:** full backend suite run again at the end of this phase, after all investigation. Result: **2,792 passed, 0 failed, 0 errors, 0 skipped** — identical to the start-of-phase baseline in Section 1. `git status` confirmed identical file footprint to the start of this phase. No script leaked state (none were run against the live tree).

---

## 10. The Phase 06 Implementation Plan

**Exact files, in order:**

1. **`src/kingsec/application/submit_assessment.py`** — the only production file requiring a logic change. After `assessment.record_scanner_summary(ran_summaries + preplanned_skips)` (currently line 282) and before `assessment.complete()` (currently line 284), add a check: if every *attempted* (non-`skipped`) entry in `ran_summaries` has `status == "failed"`, call `assessment.fail(...)` instead, with a message built per Section 8's scanner-name-based design (reusing or extending the `safe_failure_message`-style helper in `_support.py`) rather than `assessment.complete()`.
2. **`src/kingsec/application/_support.py`** — add the scanner-name-based message-composition helper from Section 8 (a new, small function alongside `safe_failure_message`), and/or extend `safe_failure_message` itself if the same sanitization split (`KingSecError`/`ApplicationError`/generic) is reused for compositing per-scanner reasons.
3. **`src/kingsec/adapters/inbound/web/execution_routes.py`** — apply sanitization to `sp.error` before it reaches `_scanner_progress_to_dict()`'s output, closing Section 8's finding. This is a **separate, independently-shippable fix** from item 1 — it can land in the same Phase 06 or be split out, but must not be forgotten now that it has been found and is no longer merely suspected.
4. **Do not touch:** `start_assessment.py` (Section 7 — unreachable, out of scope for the fix itself, though its existence and the reachability finding should be noted in Phase 06's own report), any of the 9 scanner adapters or their guard clauses (explicitly out of scope per this prompt's §3 and Phase 04 §7's own finding that it changes nothing customer-visible alone), the `_logger.debug`/`_logger.warning` inconsistency (explicitly deferred, same reasoning), and `ScannerPort`/`ScannerExecutor`'s contracts (Section 4's decision defers this).

**Exact tests to add:**
- Regression coverage for `submit_assessment.py`'s new branch, covering every row of Section 5's policy table that changes behavior: all-failed → `FAILED` with a scanner-name-based reason (not raw text); some-failed/some-succeeded-with-findings → still `COMPLETED`; some-failed/zero-findings → still `COMPLETED` (both to prove the *policy*, not just the *code path*, is what Phase 06 implements — matching Section 5's explicit decision, not an accidental default).
- A test proving the new failure message contains scanner names/counts and does **not** contain any raw exception text — mirroring Phase 03's `test_assessment_failure_sanitization.py` pattern directly.
- A test for `execution_routes.py`'s sanitized `error` field, proving a raw/unsafe underlying exception no longer reaches the HTTP response verbatim — same real-HTTP-boundary pattern Phases 01–03 already established (`TestClient` + real route + real dependency wiring, not `dependency_overrides` bypassing the mechanism under test).

**Existing tests that assert the current, defective behavior and will need deliberate, explicit replacement (not silent deletion) — verified and completed from Phase 04 §10.5's candidate list:**
- `tests/unit/infrastructure/scanner/test_orchestrator.py::TestExecuteAll::test_one_plugin_fails_others_continue` (line 256) — currently asserts `len(results) == 1` when one of two plugins fails; this specific assertion is about `execute_all()`'s *return shape*, which Section 4's chosen Option A does **not** change (Option A only changes what `submit_assessment.py` does with `execution_engine` state, not what `execute_all()` returns) — **on reflection, this test does not actually need to change under the chosen Option A**, only under a future Option B2. Recording this explicitly since Phase 04 named it as a candidate without yet knowing which option would be chosen.
- `tests/unit/infrastructure/scanner/test_orchestrator.py::TestScan::test_empty_findings` and `::test_empty_registry` (lines 362, 369) — same reasoning: these assert `scan()`'s return shape, which Option A does not touch. **Also do not need to change under Option A.**
- **The test that actually will need to change under Option A:** none currently exist that assert `submit_assessment.py`'s completion decision is unconditional — Phase 04 §6 confirmed (Section 2 above, re-confirmed) that no test anywhere asserts "all scanners fail → still `COMPLETED`" as a *positive expectation*; this is an *absence* of coverage, not an existing test that must be overturned. The nearest existing test, `test_submit_assessment.py::TestSubmitAssessmentScanFailure::test_scan_error_marks_assessment_failed` (line 258-283, from Phase 04's own reading), tests a **single, sole scanner** raising a raw `ConnectionError` and already asserts `failed.status == AssessmentStatus.FAILED` — this passes today only because a lone failing scanner currently propagates all the way to the use case's outer `except` block via a *different* path than the swallow point (worth re-confirming precisely in Phase 06 before relying on it, flagged here rather than asserted, since this investigation did not re-trace that specific single-scanner-no-`execution_engine` control flow bit-for-bit this phase).

**Order:** item 2 (helper) before item 1 (consumer) before item 3 (independent, can be parallel or deferred to a follow-up commit) before test-writing for each.

---

## 11. What Could Not Be Decided Without Product-Owner Input

1. **The exact shape of the "advisory signal" for the partial-failure case** (Section 5's open direction — a new boolean field? a warning severity level? reuse of an existing field?). This phase deliberately stopped at "COMPLETED needs *something* visible beyond `scanner_summary`" and did not design the field, because doing so would cross into implementation detail this phase is not chartered to decide. **Specific question for the product owner: should this be a simple boolean (`has_scanner_failures`), a small structured summary (count + names), or should the frontend instead always render `scanner_summary` prominently regardless of a new field — i.e., is this a backend contract problem or purely a frontend-priority problem?**
2. **Whether `StartAssessment` should be deleted, kept as a documented-dead alternative, or revived behind a new route** (Section 7). This phase found it unreachable and out of scope to fix, but not whether it should continue to exist at all. **Specific question: is there a product reason a synchronous, non-background scan-and-wait endpoint might be wanted later (e.g., for a fast/small-target profile), or was `SubmitAssessment` always meant to fully supersede it?**
3. **Whether to split the `execution_routes.py` sanitization fix (Section 8) into its own phase** rather than bundling it with the main partial-failure fix, given it is independently shippable and touches a different file with a different, narrower risk profile. **Specific question: does the product/security team want this treated with the same phase-by-phase rigor as the main fix (its own verify → reproduce → fix → test cycle), or is it small enough to fold into Phase 06 directly?**

---

## 12. Open Risks in the Chosen Design

- **Option A's small blast radius is also its limitation:** if a future change revives `StartAssessment` or adds a third scan-initiating path, Option A's fix must be manually duplicated or generalized — it is not structurally enforced the way a port-contract change (Option B2) would be. Section 4's stated trigger exists specifically to prevent this from being forgotten, but a trigger only works if someone remembers to check it; this is a process risk, not a technical one.
- **The "all attempted scanners failed" check's exact definition needs precision in Phase 06, not left implicit.** "Every non-skipped entry has `status == 'failed'`" sounds simple but needs a decided answer for edge cases this phase did not exhaustively enumerate — e.g., a scanner whose `ScannerProgress.status` is still `"running"` or `"pending"` at the moment `ran_summaries` is built (a timing/ordering question about exactly when `execution_engine.get_state()` is read relative to all plugins finishing) — Phase 06 should confirm `execute_all()`'s synchronous, sequential-loop nature (`orchestrator.py:111-136` — no concurrency, no early return) makes this impossible in practice, but should state that confirmation explicitly rather than assume it.
- **The domain-constraint note in Section 5/6 (`failure_reason` only settable via `.fail()`) means the "advisory signal" for the partial case cannot literally reuse the `failure_reason` field without either relaxing that constraint (a domain change, small but real) or introducing a new field.** This phase flagged the constraint but did not resolve which path Phase 06 should take — an open risk that the two paths have different migration/compatibility implications (a new nullable field is purely additive like Phase 03's `failure_reason` was; relaxing `.fail()`'s exclusivity over `_failure_reason` changes an existing domain invariant and needs its own review).
- **The severity rating for the unsanitized `fail_scanner` finding (Section 8) is this investigation's own judgement**, not an externally validated score — a security reviewer with more context on this deployment's actual threat model (e.g., how much an authenticated-but-lower-trust user is expected NOT to see, even about their own resources) might reasonably rate it higher.

---

## Report Path

`docs/audits/KINGSEC-PHASE-05-FAILURE-INTEGRITY-DESIGN-DECISION.md`
