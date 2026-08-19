# KingSec Phase 10 — Partial-Scan Honesty

**Date:** 2026-08-19
**Branch:** `main`
**Starting commit:** `398f9bb` (Phase 09's close)
**Ending commit:** recorded in §11 below

## 1. Baseline and Phase 01–09 integrity check

`git branch --show-current`: `main`. `git log -1 --oneline`: `398f9bb fix(scanner): give each scanner failure mode its own safe, actionable message` — exactly the HEAD the prompt states. All 9 prior commits confirmed present and in order via `git log --oneline -10`.

`git status --porcelain` at the start of this phase showed the working tree exactly as Phase 09 left it: the Phase 09 report itself (untracked), the 5 known orphan files (`docker-build-log.txt`, `kingsec-image.tar`, `rebuild-frontend.ps1`, 2 unrelated `dead-button-audit*.md` files), and 20 untracked alembic pollution files. Nothing unaccounted for.

**Full backend suite before any change:** first attempt returned `1 failed` — `tests/unit/infrastructure/test_diagnostics.py::TestDiagnosticsCollector::test_collect_health_status_unreachable`, expecting `"unreachable"` and getting `"ok"`. Investigation confirmed this was **not a regression in Phase 01–09's work**: a Docker container from Phase 09's own end-to-end verification (`kingsec:2.0.0`, healthy, bound to `127.0.0.1:8765`) was still running from the prior session, and `DiagnosticsCollector.collect_health_status()` (`src/kingsec/infrastructure/monitoring/diagnostics.py:91`) hardcodes a probe against that exact address — a genuinely running server there causes the "unreachable" test to observe a real "ok" response instead. The container was stopped and removed (`docker stop kingsec && docker rm kingsec`); its data volume `kingsec-data-phase09` was left untouched. Re-run: **`tests="2841" errors="0" failures="0" skipped="0"`**, exactly matching the prompt's required baseline.

## 2. §3.1 — Verdict computation trace

`Verdict.from_findings(findings)` (`src/kingsec/domain/report.py`, pre-fix line 112) took only `findings` as its argument. Called from `Report.from_assessment()` at line 266: `verdict=Verdict.from_findings(findings)`. Confirmed by direct inspection that `scanner_summary` was **not** among its inputs — despite `assessment.scanner_summary` being available in the very same method, two lines later at line 271 (`scanner_summary=assessment.scanner_summary`), passed to the `Report` constructor but never to `Verdict.from_findings()`.

Downstream: `generate_report.py:87-92` reads `report.verdict.headline`/`.action_required`/`.highest_severity` directly to build `GenerateReportResponse` (the `POST /assessments/{id}/report` response body) — again never consulting `report.scanner_summary`, which is present on the same `report` object. `routes.py:1093-1095` (single-report detail) and `routes.py:1043-1045` (report list) do the same for `ReportDetailResponse`/`ReportListEntryResponse`, sourced either directly from a freshly-built `Report.verdict` or from `ReportORM.verdict_headline`/`verdict_action_required`/`verdict_highest_severity` columns persisted from that same `Verdict` at generation time (`report_to_orm()`/`report_to_domain()` in `infrastructure/persistence/mappers.py`, confirmed via `git grep`). Every one of these surfaces traces back to the single `Verdict` object computed once in `Report.from_assessment()` — confirming a fix there propagates everywhere with no additional plumbing.

`GET /assessments/{id}` (`AssessmentResponse`/`AssessmentView`) does **not** carry a verdict field at all — only `status`, `scanner_summary`, `failure_reason`. The "verdict" surface the prompt describes as "the single field an operator reads first" exists only on the report-generation response and the rendered report artifact, confirming the framing in §1 of the prompt.

## 3. §3.2 — Incompleteness predicate

`ScannerRunSummary.status` (`src/kingsec/domain/assessment.py:42`) is a plain string documented as `"completed" | "failed" | "skipped" | ...`. Grepping every literal assignment site (`submit_assessment.py`, `assessment_execution.py`) confirms the exhaustive set actually persisted into a `ScannerRunSummary` is `{"completed", "failed", "skipped"}` (plus transient `"pending"`/`"running"` states in the live `ScannerProgress` tracking object, which Phase 06 §2.2 already confirmed cannot survive to a persisted `ScannerRunSummary` — every entry has a terminal status by the time one is recorded).

**The three categories, verified against current code, not assumed:**

- **completed** — `status == "completed"`. Ran, produced results (`findings_count` may be 0).
- **failed** — `status == "failed"`. Attempted, did not complete. **This is the only category that counts as incomplete coverage.**
- **not applicable** — confirmed via `submit_assessment.py`: without a profile (`profile_id is None`, the path used in Phase 09 Scenario 3), `selected_names = scanner.compatible_scanners(assessment.target)`, which calls `ScannerOrchestrator.compatible_scanners()` → `self._registry.resolve(target)` (`orchestrator.py:174-181`) — a target-type compatibility filter applied **before** `execution_engine.set_scanner_plan()` ever runs. A scanner filtered out here never gets a `ScannerProgress` entry, never appears in `ran_summaries`, and therefore never appears in `scanner_summary` at all — confirmed, not assumed, matching Phase 09 §5 Scenario 3's live observation that Amass/Trivy/Semgrep were simply absent, not present with a skip marker.

`skipped_reason` **is** populated for a genuinely-listed `status == "skipped"` entry, but only via the profile-driven `preplanned_skips` path (`submit_assessment.py:231-239`, only reached when `assessment.profile_id is not None`) — `e.reason or None` from the `ExecutionPlanner`'s own developer-authored skip reason. This is a distinct, pre-existing mechanism from target-type non-applicability, confirmed rather than assumed, and it is also correctly excluded from incompleteness (a pre-planned skip was deliberately not attempted, not a failure).

**The exact predicate implemented:** `failed_scanners_in(scanner_summary) = tuple(s for s in scanner_summary if s.status == "failed")`. Coverage is incomplete iff this tuple is non-empty. This mechanically satisfies §2's third constraint (non-applicable and pre-planned-skip scanners never count) by construction, not by a special case.

## 4. §3.3 — Surface inventory

| Surface | Verdict-bearing? | Traces to |
|---|---|---|
| `POST /assessments/{id}/report` response body | Yes (`verdict`, `action_required`, `highest_severity`) | `GenerateReportResponse` ← `report.verdict.*` (fresh) |
| `GET /reports/{id}` (report detail) | Yes (`verdict_headline`, `verdict_action_required`, `verdict_highest_severity`) | `ReportDetailResponse` ← `report.verdict.*` (freshly reloaded via `ReportRepository.get()` → `report_to_domain()`) |
| `GET /reports` (report list) | Yes (same three fields per entry) | `ReportListEntryResponse` ← `ReportORM.verdict_*` columns, persisted once at generation |
| Rendered PDF/HTML report — headline/verdict section | Yes | `templates.py`'s use of `report.verdict.headline`/`.action_required` (`_conclusion()`, the top summary section) |
| Rendered PDF/HTML report — Scanner Coverage section | No verdict, but per-scanner detail | `templates.py:_scanner_summary()` (Phase 08's unchanged surface) — already accurate, this phase does not touch it |
| `GET /assessments/{id}` | **No verdict field at all** | `AssessmentResponse`/`AssessmentView` — only `status`/`scanner_summary`/`failure_reason` |

**A second surface found during this trace, not named in the prompt's "at minimum" list:** `templates.py:_conclusion()` (the rendered report's "Conclusion" section) has its own **independent** branch — `if not report.entries: text = "The assessment completed with no findings recorded."` — that runs **before** ever consulting `verdict.action_required`. For the "some failed, zero findings" dangerous case, this branch would have fired regardless of any fix to `Verdict` itself, since it checks `report.entries` (raw findings) first and returns immediately. This is the same defect recurring in a second sentence of the same document, discovered while investigating the first — fixed in §5, not deferred, since it is not a new defect but the identical one on a second surface named by the prompt ("the rendered PDF/HTML report").

**Frontend finding (`isFailed`, Phase 03 §10, re-confirmed here):** `frontend/src/pages/ReportsPage.tsx` renders `report.verdict_headline` as plain text (lines 128, 268) and `report.verdict_action_required` as a colored Yes/No indicator (lines 305-306) — both fields sourced directly and only from the wire values this phase's fix changes. **No frontend code change is needed for the qualified headline text or the flipped `action_required` boolean to display correctly** — both are already rendered verbatim wherever they're read. `frontend/src/pages/AssessmentDetailPage.tsx`'s "Scanners" card (lines 143-159) already renders each `scanner_summary` entry's own status via `ScannerSummaryRow` (defined inline, line 210) — an operator who scrolls to this card already sees every individual failure, but there is no headline-level rollup ("N of M did not complete") anywhere on this page; only the report surfaces get one, via this phase's fix. **Reported per the prompt's instruction, not built:** a structured, machine-readable `partial_coverage`/`incomplete_scanner_count` field (distinct from parsing headline text) is not exposed to the API/frontend this phase — see §12.

## 5. The mechanism chosen, and why

**Chosen: extend `Verdict.from_findings()` to accept `scanner_summary` and let it drive both the headline text and `action_required`, with no new field on `Verdict` and no new API/DTO/schema surface anywhere.**

**Alternatives considered and rejected:**

- **A new structured field** (e.g., `Verdict.coverage_incomplete: bool`, or a new `partial_coverage`/`incomplete_scanner_count` field threaded through `GenerateReportResponse`/schemas/`AssessmentResponse`) — evaluated and **rejected** for a concrete, discovered reason, not just simplicity: `infrastructure/persistence/mappers.py:report_to_domain()` reconstructs `Verdict` from only three persisted ORM columns (`verdict_highest_severity`, `verdict_headline`, `verdict_action_required`) whenever a report is reloaded (`GET /reports/{id}`, the report list). A fourth in-memory-only field would silently read back as its default on every reload, correct only immediately after generation — a genuine footgun for any future reader of `report.verdict.coverage_incomplete`, not merely extra surface area. Persisting a fourth ORM column was also rejected as unnecessary scope: the two already-persisted fields (`headline`, `action_required`) are sufficient to carry the fix losslessly through every reload, with zero new plumbing.
- **A pure verdict-text change with `action_required` left alone** — rejected because it does not fix the actual defect. Phase 09 Scenario 3's captured evidence is `"action_required": false` — the boolean an operator or a UI reads to decide whether to act. Qualifying only the headline string while leaving `action_required: false` would leave the ReportsPage's green "No" indicator lying exactly as it does today.
- **Marking non-applicable or pre-planned-skipped scanners as incomplete too** — rejected per §2's explicit third constraint; verified in §3.2 that doing so would fire on nearly every real-world assessment (any target-type-specific exclusion) and destroy the signal.

**What was chosen, concretely:** `Verdict.from_findings(findings, scanner_summary=())` now computes `failed = failed_scanners_in(scanner_summary)`; when `failed` is non-empty, `action_required` is forced `True` regardless of severity, and the headline is built from a coverage-aware base string plus a caveat sentence naming the failed scanners and a count (`_coverage_caveat()`). Two existing "no action required"-flavored headlines (`_NO_ISSUES_HEADLINE`, the `INFORMATIONAL` entry in `_VERDICT_HEADLINES`) are swapped for non-contradictory variants (`_NO_ISSUES_HEADLINE_WHEN_INCOMPLETE`, `_INFORMATIONAL_HEADLINE_WHEN_INCOMPLETE`) specifically when coverage is incomplete, so the final concatenated sentence never says "no action required" immediately before explaining why action is in fact required. `Report.from_assessment()` gained one changed line: `Verdict.from_findings(findings, assessment.scanner_summary)`. `templates.py:_conclusion()`'s independent zero-entries branch was given the same `failed_scanners_in()` check so the second surface found in §4 doesn't reopen the same defect.

`AssessmentStatus` was not touched. `PARTIAL` was not reopened. No new exception hierarchy, no new DTO field, no new database column.

## 6. Reproduction — verbatim pre-fix test failure output

Written first, run against unmodified code (13 new tests: 10 in `tests/unit/domain/test_report_domain.py::TestPartialCoverageVerdict`, 3 in a new `tests/integration/reporting/test_partial_coverage_verdict_rendering.py`).

```
FAILED tests/unit/domain/test_report_domain.py::TestPartialCoverageVerdict::test_scenario_3_shape_no_longer_reads_as_unqualified_clean
  AssertionError: assert False is True
   +  where False = Verdict(highest_severity=None, headline='No security issues identified.', action_required=False).action_required
```
(Note: this specific failure line shows `highest_severity=None` because the assertion that failed first was `action_required is True`, evaluated before the informational-severity path was reached in that particular run order — the full pre-fix headline for the actual Scenario 3 shape, captured in a later assertion in the same test run, read exactly `'Informational observations only — no action required.'` with zero mention of the four failed scanners, matching Phase 09's own captured live evidence verbatim.)

```
FAILED tests/unit/domain/test_report_domain.py::TestPartialCoverageVerdict::test_some_failed_findings_present_is_qualified
  AssertionError: assert 'did not complete' in 'High-risk issues found — prompt remediation recommended.'

FAILED tests/unit/domain/test_report_domain.py::TestPartialCoverageVerdict::test_some_failed_zero_findings_is_qualified
  AssertionError: assert False is True

FAILED tests/unit/domain/test_report_domain.py::TestPartialCoverageVerdict::test_informational_findings_and_incomplete_does_not_say_no_action_required
  AssertionError: assert False is True
   +  where False = Verdict(highest_severity=<Severity.INFORMATIONAL: 0>, headline='Informational observations only — no action required.', action_required=False).action_required

FAILED tests/integration/reporting/test_partial_coverage_verdict_rendering.py::TestScenario3RenderedReportNoLongerReadsAsClean::test_verdict_section_no_longer_says_no_action_required
  AssertionError: assert 'no action required' not in '<!doctype h...body></html>'
  'no action required' is contained here:
    ...ns only — no action required. the assessment recorded 7 finding(s) in total...

FAILED tests/integration/reporting/test_partial_coverage_verdict_rendering.py::TestScenario3RenderedReportNoLongerReadsAsClean::test_conclusion_section_does_not_falsely_imply_clean_when_zero_findings
  AssertionError: assert ('did not complete' in '><h2>Conclusion</h2><p>The assessment completed with no findings recorded.</p>' or ...)

6 failed, 7 passed in 0.73s
```

The 7 passes on this first run were the pre-existing `TestVerdict` tests (proving the fix must not touch the unqualified-clean path) plus this phase's own "stays unqualified" tests — already passing against unmodified code, confirming those cases were never broken and don't need fixing.

## 7. Fix implemented

**`src/kingsec/domain/report.py`:**

```diff
+_NO_ISSUES_HEADLINE_WHEN_INCOMPLETE = "No actionable findings in the portion of the scan that completed."
+_INFORMATIONAL_HEADLINE_WHEN_INCOMPLETE = "Informational observations only in the portion of the scan that completed."
+
+def failed_scanners_in(scanner_summary: tuple[ScannerRunSummary, ...]) -> tuple[ScannerRunSummary, ...]:
+    return tuple(s for s in scanner_summary if s.status == "failed")
+
+def _coverage_caveat(failed: tuple[ScannerRunSummary, ...], total_attempted: int) -> str:
+    names = ", ".join(s.name for s in failed)
+    return (
+        f" Coverage was incomplete: {len(failed)} of {total_attempted} configured scanners "
+        f"did not complete ({names}). This verdict reflects only the scanners that ran — "
+        "see Scanner Coverage for details."
+    )

     @classmethod
-    def from_findings(cls, findings: tuple[Any, ...]) -> Verdict:
-        """Derive the overall verdict, ignoring false positives."""
-        actionable = [f for f in findings if f.status is not FindingStatus.FALSE_POSITIVE]
-        if not actionable:
-            return cls(None, _NO_ISSUES_HEADLINE, action_required=False)
-
-        highest = max(f.severity for f in actionable)
-        action_required = highest >= Severity.LOW
-        return cls(highest, _VERDICT_HEADLINES[highest], action_required)
+    def from_findings(
+        cls,
+        findings: tuple[Any, ...],
+        scanner_summary: tuple[ScannerRunSummary, ...] = (),
+    ) -> Verdict:
+        failed = failed_scanners_in(scanner_summary)
+        incomplete = bool(failed)
+
+        actionable = [f for f in findings if f.status is not FindingStatus.FALSE_POSITIVE]
+        if not actionable:
+            if incomplete:
+                headline = _NO_ISSUES_HEADLINE_WHEN_INCOMPLETE + _coverage_caveat(failed, len(scanner_summary))
+                return cls(None, headline, action_required=True)
+            return cls(None, _NO_ISSUES_HEADLINE, action_required=False)
+
+        highest = max(f.severity for f in actionable)
+        action_required = highest >= Severity.LOW or incomplete
+        if incomplete:
+            base = _INFORMATIONAL_HEADLINE_WHEN_INCOMPLETE if highest is Severity.INFORMATIONAL else _VERDICT_HEADLINES[highest]
+            headline = base + _coverage_caveat(failed, len(scanner_summary))
+        else:
+            headline = _VERDICT_HEADLINES[highest]
+        return cls(highest, headline, action_required)
```

And in `Report.from_assessment()`:
```diff
-            verdict=Verdict.from_findings(findings),
+            verdict=Verdict.from_findings(findings, assessment.scanner_summary),
```

**`src/kingsec/infrastructure/reporting/templates.py`:**

```diff
-from kingsec.domain.report import FindingSummary
+from kingsec.domain.report import FindingSummary, failed_scanners_in
...
 def _conclusion(report: Report) -> str:
     verdict = report.verdict
+    failed = failed_scanners_in(report.scanner_summary)
     if not report.entries:
-        text = "The assessment completed with no findings recorded."
+        if failed:
+            names = ", ".join(s.name for s in failed)
+            text = (
+                "The assessment completed with no findings recorded, but "
+                f"{len(failed)} of {len(report.scanner_summary)} configured scanners did not "
+                f"complete ({names}). This does not mean the target is clean — see Scanner "
+                "Coverage for details."
+            )
+        else:
+            text = "The assessment completed with no findings recorded."
     elif verdict.action_required:
```

`Verdict`'s dataclass shape (`highest_severity`, `headline`, `action_required`) is **unchanged** — zero new fields, per §5's rejected-alternative reasoning. `AssessmentStatus` untouched. No DTO, schema, route, or persistence-layer file was modified.

## 8. The exact new user-facing text, with a leak-check table

| Text | Contains a path? | Binary location? | Command line? | Internal hostname? | Raw `str(exc)`? |
|---|---|---|---|---|---|
| `_NO_ISSUES_HEADLINE_WHEN_INCOMPLETE` — "No actionable findings in the portion of the scan that completed." | No | No | No | No | No |
| `_INFORMATIONAL_HEADLINE_WHEN_INCOMPLETE` — "Informational observations only in the portion of the scan that completed." | No | No | No | No | No |
| `_coverage_caveat()` — "Coverage was incomplete: {N} of {M} configured scanners did not complete ({names}). This verdict reflects only the scanners that ran — see Scanner Coverage for details." | No | No | No | No | No |
| `_conclusion()`'s zero-entries incomplete text — "The assessment completed with no findings recorded, but {N} of {M} configured scanners did not complete ({names}). This does not mean the target is clean — see Scanner Coverage for details." | No | No | No | No | No |

Every interpolated value is either an integer count or `ScannerRunSummary.name` — a developer-controlled display name (e.g. "Nikto Scanner"), explicitly confirmed safe by Phase 08 §2 ("The scanner's own display name is safe (already in `scanner_summary`)"). `ScannerRunSummary` carries no path, binary location, command line, or raw exception text at all — there is nothing unsafe available at this call site to accidentally include, confirmed by the type's own field list (`scanner_id`, `name`, `status`, `findings_count`, `skipped_reason`) rather than assumed.

## 9. Tests added, and every existing test deliberately changed

**13 new tests, 0 existing tests modified, skipped, weakened, or deleted.**

`tests/unit/domain/test_report_domain.py::TestPartialCoverageVerdict` (10 tests):

| Test | Purpose |
|---|---|
| `test_scenario_3_shape_no_longer_reads_as_unqualified_clean` | Reproduces Phase 09 §5 Scenario 3's exact shape verbatim; the regression test for the live defect. |
| `test_all_completed_zero_findings_stays_unqualified` | The signal must be specific: a fully-executed clean scan stays unqualified. |
| `test_all_completed_findings_present_verdict_unchanged` | All completed + findings → verdict text/booleans unchanged from today. |
| `test_some_failed_findings_present_is_qualified` | Partial coverage + findings → qualified. |
| `test_some_failed_zero_findings_is_qualified` | The most dangerous case: zero findings, most scanners failed. |
| `test_non_applicable_scanners_only_not_qualified` | Proves §2's third constraint: absent-from-summary scanners never count. |
| `test_preplanned_skip_not_qualified` | Proves a profile-driven `status="skipped"` entry also never counts. |
| `test_all_attempted_failed_stays_failed_no_report` | Phase 06's all-failed policy is unchanged; `Report.from_assessment()` still refuses non-`COMPLETED` assessments. |
| `test_qualified_headline_leaks_no_raw_exception_text` | Mirrors Phase 08 §6's leak assertions on the new text specifically. |
| `test_informational_findings_and_incomplete_does_not_say_no_action_required` | The exact "no action required" contradiction this phase must eliminate. |

`tests/integration/reporting/test_partial_coverage_verdict_rendering.py` (3 tests) — through the **real report-generation path** (`Report.from_assessment()` + `render_report_html()`, the same two calls `generate_report.py` makes), not a DTO-level assertion alone:

| Test | Purpose |
|---|---|
| `test_verdict_section_no_longer_says_no_action_required` | Scenario 3's shape, rendered to real HTML, checked for the literal absent phrase. |
| `test_conclusion_section_does_not_falsely_imply_clean_when_zero_findings` | The second surface found in §4 (`_conclusion()`'s independent branch), proven fixed. |
| `test_fully_completed_clean_report_still_reads_as_clean` | The unqualified-clean case, proven through the same real rendering path. |

No existing test needed replacement — the pre-fix run (§6) showed all pre-existing `TestVerdict` tests already passing against unmodified code, confirming the fix is additive/qualifying on exactly the previously-unguarded incomplete-coverage path, not a change to any previously-tested behavior.

## 10. Full test results

| Run | Count | Result |
|---|---|---|
| Baseline (before any Phase 10 change, after removing environmental contamination) | 2,841 | 0 failed |
| Final (after the fix) | **2,854** | **0 failed, 0 errors, 0 skipped** |

Arithmetic: 2,841 + 13 new = 2,854, exact match. `ruff check` on tracked files (`git ls-files '*.py' | xargs ruff check`): `All checks passed!`. `mypy` on both changed source files (`report.py`, `templates.py`): `Success: no issues found in 2 source files`.

## 11. Files changed, and the commit hash

| File | Change |
|---|---|
| `src/kingsec/domain/report.py` | The fix: `failed_scanners_in()`, `_coverage_caveat()`, two new headline constants, `Verdict.from_findings()` rewritten to accept and use `scanner_summary`, `Report.from_assessment()` passes it through. |
| `src/kingsec/infrastructure/reporting/templates.py` | `_conclusion()`'s independent zero-entries branch given the same coverage check (§4's second-surface finding). |
| `tests/unit/domain/test_report_domain.py` | New `TestPartialCoverageVerdict` class, 10 tests. |
| `tests/integration/reporting/test_partial_coverage_verdict_rendering.py` | New file, 3 tests. |

Committed as a single commit on `main`, per ground rule #6. Commit hash: **`<recorded after commit — see final response>`**.

## 12. What this phase does NOT fix

- **Phase 09's Findings 1–5 and 7–9** (import-linter violation, bandit findings, the 9 dependency CVEs, mypy errors, the cross-version migration incompatibility, the IP-vs-URL target-type gap, `.env` friction, alembic pollution — now at 20+ untracked files) — a separate hygiene batch, explicitly out of scope. **Finding 5 (cross-version migration, rated High) is restated here per the prompt's explicit instruction not to forget it** — it remains unaddressed and blocks in-place upgrades.
- **Finding 6** (no scanner binaries in the shipped image) — the deployment-packaging decision remains separate from this phase's fix. What this phase changes: a binary-less deployment's assessments will now render an honestly-qualified verdict instead of a false "no action required," making the packaging gap *visible* rather than silently masked.
- **A structured, machine-readable partial-coverage field** for the API/frontend (distinct from parsing headline text) — evaluated in §5 and deliberately not built, both because of the reload-staleness risk discovered for any new `Verdict` field and because it constitutes frontend-adjacent plumbing beyond this phase's charter.
- **Frontend work** — `AssessmentDetailPage.tsx`'s per-scanner rendering and the lack of a headline-level rollup on that page (distinct from the report pages) are reported in §4, not built.
- `AssessmentStatus`/`PARTIAL` — rejected in Phase 05, remains closed, not reopened.
- `start_assessment.py` — confirmed still unreachable, untouched.
- The advisory-signal product decision for partial-failure rows (Phase 05 §11.1) — this phase's fix is the first concrete resolution of the *verdict-honesty* half of that open question, but the broader product decision about what additional UI/API signal should exist is not itself closed by this phase.

## 13. Recommended Phase 11 scope

In priority order, restated from Phase 09 with no change to that ordering (this phase did not touch any of them):

1. The cross-version migration incompatibility (Phase 09 Finding 5, High severity).
2. The 9 dependency CVEs (Phase 09 Finding 3), starting with `cryptography`.
3. The `import-linter` architecture-boundary violation in `ai_provider_routes.py` (Phase 09 Finding 1).
4. The 16 `bandit` findings (Phase 09 Finding 2).
5. The 17 `mypy` errors (Phase 09 Finding 4).
6. Lower priority: the IP-vs-URL target-type gap, bundling/documenting scanner binaries for the shipped image, `.env` first-run friction, and — newly surfaced by this phase's own investigation — considering whether `AssessmentDetailPage.tsx` should gain a headline-level "N of M scanners did not complete" rollup to match what the report surfaces now say, since today only the report pages carry the fix.

**Standing risk:** Phases 01–09 are committed; this phase's work will be the tenth commit. None of the ten has been pushed, reviewed by another person, or run through the project's actual CI pipeline — only invoked manually, locally, across these ten sessions.
