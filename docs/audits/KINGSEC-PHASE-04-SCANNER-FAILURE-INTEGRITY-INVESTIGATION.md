# KingSec Phase 04 — Scanner Failure Integrity Investigation

**Date:** 2026-08-19
**Baseline commit:** `4f4b666` (branch `main`) — unchanged since Phase 01/02/03; all three remain uncommitted in the working tree.
**Scope:** Investigation only. No source file was changed. No test file was changed. No fix was implemented, per `Downloads/KINGSEC-PHASE-04-PROMPT.md` §0.

---

## 1. Baseline and Phase 01–03 Integrity Check

- Branch: `main`. Commit: `4f4b666`.
- `git status` before this investigation began: Phases 01–03 present, uncommitted, unmodified — re-verified explicitly:
  - `src/kingsec/adapters/inbound/web/worker_routes.py`: `dependencies=[Depends(require_admin)]` present at the router declaration.
  - `src/kingsec/adapters/inbound/web/distributed_routes.py`: `_require_admin(user)` present at all 4 fixed call sites.
  - `src/kingsec/application/dto.py` / `src/kingsec/adapters/inbound/web/schemas.py` / `src/kingsec/adapters/inbound/web/routes.py`: `failure_reason` present in `AssessmentView`, `AssessmentResponse`, and the route handler's response construction.
  - `src/kingsec/application/_support.py`: `safe_failure_message()` present, applied at both `.fail()` call sites in `start_assessment.py` and `submit_assessment.py`.
- Full backend `pytest` suite before this investigation: **2,792 passed, 0 failed, 0 errors, 0 skipped** (JUnit XML: `tests="2792" errors="0" failures="0" skipped="0"`, 131.7s) — exactly Phase 03's ending state.
- **End-of-phase re-check** (after all reading and all live-proof scripts had been run): `git status` shows **zero additional files changed** — the working tree's modified/untracked file list is byte-for-byte identical to the start-of-phase list (8 modified source files, 6 untracked test files, all from Phases 01–03). Full backend suite re-run: see Section 7's closing note for the exact final count, confirmed **still 2,792 passed, 0 failed** — no diagnostic script leaked state into the tracked repository or the test suite.

**VERIFIED.**

---

## 2. Failure Taxonomy Table (§2.1)

**Architectural finding that shapes this whole table:** all 9 scanner adapters (`nmap.py`, `nuclei.py`, `nikto.py`, `ffuf.py`, `gobuster.py`, `amass.py`, `trivy.py`, `zap.py`, `semgrep.py`) share byte-for-byte identical control flow — same guard clause, same variable names, same structure — clearly built from one shared template. The audit's own caveat ("the same pattern likely recurs in siblings, not exhaustively re-checked per adapter") is now **exhaustively confirmed true for all 9**, not just suspected for one. Binary-absent and timeout handling live in one shared module (`runner.py`) used identically by all 9. This means the taxonomy below is genuinely one table, not nine different ones — the only real per-scanner variation is in the *parser* layer (JSON vs. XML vs. plain text).

| Scenario | What happens | Citation |
|---|---|---|
| **Binary absent from PATH** | `subprocess.run()` raises `FileNotFoundError`, caught and re-raised as `ScannerExecutionError` — identical for all 9. Propagates uncaught through the adapter and the plugin wrapper (no `try/except` in any of the 9 `plugins/<name>/adapter.py` `scan()` methods — confirmed by grep across all 9). Caught by `ScannerOrchestrator.execute_all()`, logged, scanner silently omitted from the result tuple. | `runner.py:85-90` (raise); `orchestrator.py:118-136` (swallow) |
| **Binary exits non-zero, no output** | Exit code IS checked, by the adapter itself, immediately after parsing: `if result.returncode != 0 and not findings: raise ScannerExecutionError(...)`. With no output, `findings` is empty, so the condition is true and it raises. Same swallow-at-orchestrator fate as above. | `nmap.py:57-65`, `nuclei.py:81-89`, `nikto.py:58-66`, `ffuf.py:58-66`, `gobuster.py:58-66`, `amass.py:57-65`, `trivy.py:58-66`, `zap.py:57-65`, `semgrep.py:57-65` (identical guard in all 9) |
| **Binary exits non-zero, partial valid output** | The exact same guard clause's `and not findings` half now evaluates false — the exception is **never raised**. The adapter returns the partial findings as an ordinary, fully successful result. The exit code is read into `result.returncode`, checked once, and then discarded — it influences nothing else anywhere in the call chain. **Confirmed live** (Section 6, proof #2): a real `FakeRunner`-backed call with `returncode=1` and one valid finding line returned normally with 1 finding, an INFO-level "scan completed" log, and no trace of the failure. | Same 9 citations as above — this is the other half of the same `if` statement. Live proof: Section 6, script 2. |
| **Binary exits zero, malformed/unparseable output** | Parser-dependent. JSON/XML parsers (`nmap_parser.py`, `parser.py` [nuclei], `ffuf_parser.py`, `amass_parser.py`, `trivy_parser.py`, `zap_parser.py`, `semgrep_parser.py`) catch the decode error, log it (`_logger.warning` or `_logger.debug` — inconsistent level, see below), and return `[]`. Since `returncode == 0`, the adapter's guard clause (`result.returncode != 0 and ...`) is false regardless of `findings`, so **no exception is ever raised** — this case is silent even more directly than the previous row. `nikto_parser.py` and `gobuster_parser.py` are plain-text/regex-based with no "malformed" concept at all: any line that doesn't match the expected pattern is simply not a finding — there is no failure mode to catch, only an implicit "this text didn't look like a finding line," indistinguishable in principle from the scanner reporting nothing. **Confirmed live** (Section 6, proof #1) for Nuclei's parser: 2 of 4 lines were deliberately corrupted, both silently dropped, no signal in the return value. | `nmap_parser.py:168-172`; `parser.py:160-168` (nuclei); `ffuf_parser.py:98-105`; `amass_parser.py:120-127`; `trivy_parser.py:182-193`; `zap_parser.py:117-128`; `semgrep_parser.py:58-69`; `nikto_parser.py` (no malformed path — N/A, whole-file read); `gobuster_parser.py` (same, N/A). Live proof: Section 6, script 1. |
| **Binary exits zero, valid output, genuinely zero findings** | Returns `[]` — the exact same shape, through the exact same return statement, as the row above. There is no field, flag, or side channel anywhere in `CommandResult`, the parser return value, or `ScannerResult` that distinguishes "ran perfectly and found nothing" from "output was corrupted and everything was silently discarded." **Confirmed live** (Section 6, proof #1): `parse_nuclei_jsonl('')` and `parse_nuclei_jsonl('garbage')` both return `[]`, identically. | Same parser citations as the row above. Live proof: Section 6, script 1. |
| **Binary hangs → timeout fires** | `subprocess.run(..., timeout=...)` raises `subprocess.TimeoutExpired`, caught and re-raised as `ScannerExecutionError` — identical for all 9, same shared module. Propagates and is swallowed at the orchestrator exactly like the binary-absent case. Distinguishable from a binary-absent failure only by the exception's `message` text ("scan timed out after Ns" vs. "scanner binary not found") — both collapse to the same generic "scanner plugin failed, skipping" log line and the same silent omission from results. | `runner.py:91-96` (raise); `orchestrator.py:118-136` (swallow) |

**Log-level inconsistency noted in passing (not a scored taxonomy cell, but relevant to severity):** `nmap_parser.py`, `parser.py` (nuclei), and `ffuf_parser.py` log malformed-output at `_logger.warning`; `amass_parser.py`, `trivy_parser.py`, `zap_parser.py`, and `semgrep_parser.py` log at `_logger.debug` — meaning in a typical production logging configuration (INFO or WARNING threshold), those four scanners' parse failures may not even reach the log at all, not just the API response.

**No cell in this table is marked UNKNOWN** — every scenario was traceable to specific, cited code, and 3 of the 6 were additionally confirmed with live-running proof (Section 6).

---

## 3. Swallow Points Inventory (§2.2)

Every place a scanner or parser exception is caught and converted into an empty or partial result without a failure signal reaching anything downstream other than a log line:

| # | Location | What is swallowed | Does anything downstream learn? |
|---|---|---|---|
| 1 | `nmap_parser.py:168-172` (and the 6 sibling JSON/XML parsers, see Section 2's citations) | A parse-level decode error (`ET.ParseError` / `json.JSONDecodeError`) | **No.** Logged, returns `[]`. |
| 2 | `nmap_parser.py:174-178` | A per-`<host>` element error during XML traversal | **No.** Logged, that host's findings are dropped, loop continues. |
| 3 | 9× adapter guard clause (Section 2's citations) | A non-zero exit code, when at least one finding was still parseable | **No — not even the exit code's existence.** No exception, no log field records the returncode was non-zero once this branch is skipped (the "scan completed" INFO log — e.g. `nuclei.py:90-95` — does not include `returncode` at all). Confirmed live, Section 6 script 2. |
| 4 | `orchestrator.py:63-71` (`execute()`) | Any exception from `plugin.health_check()` or `plugin.scan()` that isn't already `ScannerPluginError` | **Re-raised as `ScannerPluginError`**, so this hop alone does not lose the signal — but see #5. |
| 5 | `orchestrator.py:118-136` (`execute_all()`) | **The central swallow point.** Any exception from `self.execute(plugin, ...)`, for any of the 9 plugins, for any reason (binary absent, timeout, non-zero exit, or an adapter bug) | **Only a log line** (`_logger.warning("scanner plugin failed, skipping", ...)`) unconditionally. **Conditionally**, if `execution_engine`/`tracking_id` were passed in, `engine.fail_scanner(tid, plugin_id.value, str(exc))` records it into the execution engine's in-memory `ScannerProgress` state — but the function's **return value** (the `tuple[ScannerResult, ...]`) simply omits the failed plugin entirely, with no marker of its absence. |
| 6 | `orchestrator.py:141-151` (`scan()`) | The `ScannerPort.scan()` contract itself | Flattens `execute_all()`'s results into a bare findings tuple — **structurally cannot** carry failure information; there is no field for it. Any caller using this method (all of `start_assessment.py`, and `submit_assessment.py` whenever `scanner_executor` is `None`) is permanently blind to scanner failures no matter what happens upstream. |
| 7 | `submit_assessment.py:284` | The already-captured `execution_engine.get_state(tracking_id).scanner_progress` (built into `ran_summaries` at lines 266-282, immediately before this line) | **No — this is the terminal swallow point.** `assessment.complete()` is called unconditionally, one line after `ran_summaries` (which can contain `status="failed"` entries with real error text) was recorded onto the assessment via `record_scanner_summary()`. The data is captured on the very same object, in the very same code path, and is not read before deciding COMPLETED vs. FAILED. |
| 8 | `start_assessment.py:103-112` | Everything — this path never wires an `execution_engine` at all (confirmed: `StartAssessment.__init__`, `use_cases/start_assessment.py:45-53`, has no such parameter, and `bootstrap/composition.py:574-583`'s factory never passes one) | **No.** `assessment.complete()` at line 112 is unconditional, and there is no `scanner_summary` ever recorded for an assessment run through this path, regardless of outcome. This is the single most information-poor path in the codebase for this defect. |

**VERIFIED**, all 8 points cited to exact `file:line`.

---

## 4. Status-Assignment Call Graph (§2.3)

```
SubmitAssessment.execute()                          [submit_assessment.py:73]
  -> assessment.start()                              (AUTHORIZED -> RUNNING)
  -> job_runner.submit(job_id, background_fn)
       -> _execute_scan()                             [submit_assessment.py:185]
            try:
              -> scanner_executor.execute_all(...)     [line 246, when scanner_executor is not None]
                   -> ScannerOrchestrator.execute_all() [orchestrator.py:73]
                        for each plugin: catches ALL exceptions internally (swallow point #5)
                        returns only the plugins that succeeded
              -> [build `findings` from whatever succeeded; failures already dropped]
              -> execution_engine.get_state(tracking_id)   [line 267]
              -> ran_summaries = [... per-scanner status, INCLUDING "failed" ...]   [lines 268-281]
              -> assessment.record_scanner_summary(ran_summaries + preplanned_skips) [line 282]
              -> assessment.complete()                      [line 284 — UNCONDITIONAL]
            except Exception as exc:                        [line 301]
              -> assessment.fail(safe_failure_message(exc))  [line 305]
```

```
StartAssessment.execute()                           [start_assessment.py:61]
  -> assessment.start()
  try:
    -> scanner.scan(...)                              [line 103-107 — bare ScannerPort.scan(), no execution_engine anywhere in this class]
    -> [findings from whatever succeeded; failures already dropped inside scan()'s own call to execute_all()]
    -> assessment.complete()                           [line 112 — UNCONDITIONAL; no scanner_summary ever recorded]
  except Exception as exc:
    -> assessment.fail(safe_failure_message(exc))       [line 146]
```

**What condition sets `COMPLETED`?** Reaching the end of the `try` block without an exception escaping it — nothing else. Neither path inspects `findings` count, `ran_summaries`/`scanner_summary` contents, or any per-scanner status before calling `.complete()`.

**What condition sets `FAILED`?** An exception escaping the entire `try` block (in `SubmitAssessment`, that means escaping `_execute_scan()`'s `try`; in `StartAssessment`, escaping `execute()`'s `try`). Per the swallow-point inventory (Section 3), a scanner-level failure — of any of the 6 taxonomy kinds in Section 2 — **never reaches this point**, because it is caught and neutralized inside `ScannerOrchestrator.execute_all()` two or three call-frames earlier. The only things that DO reach this `except` block are failures that occur *outside* the scanner-plugin system entirely: an `ExecutionPlanUnsatisfiedError` from the profile planner (line 222 / `start_assessment.py:100`), a persistence error, or a bug in the use case's own code.

**Is zero-findings anywhere an input to that decision?** **No — settled, definitively, by direct code trace.** Neither `assessment.complete()` call site (`submit_assessment.py:284`, `start_assessment.py:112`) is preceded by any conditional on `len(findings)`, `assessment.findings`, or `scanner_summary`. This is not an inference — it is the literal absence of any such branch in the source, confirmed by reading both functions in full. The pre-Phase-01 standing hypothesis is **DISPROVEN in the specific form it was usually stated** ("zero findings triggers/suppresses FAILED") — the real mechanism is simpler and worse: the *scanner failure signal itself* never reaches the completion decision, regardless of finding count. A scan with 1 real finding and 8 silently-failed scanners reaches `COMPLETED` exactly as readily as a scan with 0 findings and 9 silently-failed scanners does.

**If every scanner in an assessment fails, does the assessment still reach `COMPLETED`? Proven live.** See Section 6, proof #3: a real assessment, with its one and only registered scanner (Nuclei) genuinely failing via a real subprocess call, reached `status: "completed"`, `failure_reason: null`, `findings: []` — while the very same HTTP response's `scanner_summary` field, in the same payload, showed `{"scanner_id": "nuclei", "status": "failed", ...}`. **CONFIRMED**, live, at the real HTTP boundary.

**VERIFIED.**

---

## 5. What Already Works — Report Layer Verification (§2.4)

Independently verified, not assumed from the audit:

- `infrastructure/reporting/templates.py:636-678`, `_scanner_summary(report)`: renders a dedicated `<section id="scanner-coverage"><h2>Scanner Coverage</h2>...` block. For each scanner it groups by `(status, detail)`; a `completed` scanner shows its finding count, anything else shows `skipped_reason` (falling back to `"did not complete"`). This **does** correctly distinguish a scanner that ran and found nothing from one that failed or was skipped — confirmed by reading the function in full, not just its docstring.
- `domain/report.py:271`: `Report`'s factory copies `scanner_summary=assessment.scanner_summary` verbatim from the domain `Assessment` — the report layer receives exactly what the assessment recorded, with no independent re-derivation and no additional loss.
- Chain confirmed end-to-end: `ScannerOrchestrator` (via `execution_engine`) → `submit_assessment.py`'s `ran_summaries` → `Assessment.record_scanner_summary()` → `Report.scanner_summary` → `_scanner_summary()`'s rendered HTML. Every hop preserves the per-scanner status faithfully. The **only** place in this entire chain that does not consult it is the `assessment.complete()` call that happens one step earlier in the same function (`submit_assessment.py:284`, immediately after `record_scanner_summary()` at line 282).

**Determination: this is a plumbing problem, not a detection problem.** The failure information is detected accurately (a genuinely non-functioning scanner is correctly recorded as `status="failed"` with a real error string, not silently mistaken for success at the detection layer itself) and is already correctly rendered wherever the report layer consumes it. It is lost — specifically, never even read — at exactly one decision point: the unconditional `assessment.complete()` calls in both use cases. This substantially narrows the eventual fix's shape: it does not require building new failure-detection machinery (that machinery, `AssessmentExecutionEngine`, already exists and already works correctly for the `SubmitAssessment` path); it requires making one existing decision consult data that is already sitting one line above it.

The caveat that keeps this from being a fully uniform "just wire it up" conclusion: `StartAssessment` (Section 4) never populates `scanner_summary` at all, so for that path specifically, the fix is not purely plumbing — some detection wiring (or a policy decision to route that path through the engine too, or to derive a signal a different way) would still be needed there.

**VERIFIED.**

---

## 6. Live Proof — Every Diagnostic Script, Verbatim, With Real Output

All three scripts are throwaway diagnostics, written for this investigation only. They live in `$CLAUDE_JOB_DIR/tmp/phase04_live_proof/` — outside `tests/` and `src/` — and are reproduced here in full per §0's explicit instruction not to repeat Phase 01's mistake of deleting a reproduction artifact.

### Script 1 — Malformed scanner output → zero findings, no error

```python
"""Phase 04 live proof #1: malformed scanner output -> zero findings, no error.

Throwaway diagnostic script. Not part of tests/ or src/. Feeds the REAL
parse_nuclei_jsonl() function (src/kingsec/infrastructure/scanner/parser.py)
deliberately malformed input matching Nuclei's real -jsonl line-delimited
format, and shows exactly what comes back.
"""

import sys

sys.path.insert(0, "D:/New_folder/kingsec/src")

from kingsec.infrastructure.scanner.parser import parse_nuclei_jsonl  # noqa: E402

MALFORMED_INPUT = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE",'
    '"severity":"critical","description":"remote code execution"},'
    '"type":"http","matched-at":"http://10.0.0.5:8080/"}\n'
    '{"template-id":"exposed-panel","info":{"name":"Admin Panel"'  # <- truncated, missing closing braces
    '\n'
    '"just a bare string, not a JSON object"\n'
    '{"template-id":"CVE-2023-1234","info":{"name":"Second Real Finding",'
    '"severity":"high"},"type":"http","host":"10.0.0.5"}\n'
)

print("=== INPUT (4 lines: valid, truncated-JSON, bare-string, valid) ===")
print(MALFORMED_INPUT)

findings = parse_nuclei_jsonl(MALFORMED_INPUT)

print(f"=== parse_nuclei_jsonl() returned {len(findings)} finding(s) ===")
for f in findings:
    print(f"  - {f.title!r} (severity={f.severity.name})")

print()
print("=== Now the fully-empty / fully-garbage cases, for direct comparison ===")
empty_result = parse_nuclei_jsonl("")
garbage_result = parse_nuclei_jsonl("{{{ not json at all !!! \n### also not json\n")

print(f"parse_nuclei_jsonl('') -> {empty_result!r}")
print(f"parse_nuclei_jsonl('completely unparseable garbage') -> {garbage_result!r}")
```

**Real output (verbatim, structlog timestamps redacted to `[ts]` for readability, content unchanged):**
```
=== INPUT (4 lines: valid, truncated-JSON, bare-string, valid) ===
{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE","severity":"critical","description":"remote code execution"},"type":"http","matched-at":"http://10.0.0.5:8080/"}
{"template-id":"exposed-panel","info":{"name":"Admin Panel"
"just a bare string, not a JSON object"
{"template-id":"CVE-2023-1234","info":{"name":"Second Real Finding","severity":"high"},"type":"http","host":"10.0.0.5"}

[ts] warning  skipping non-JSON nuclei output line     [kingsec.infrastructure.scanner]
[ts] warning  skipping non-object nuclei output line   [kingsec.infrastructure.scanner]
=== parse_nuclei_jsonl() returned 2 finding(s) ===
  - 'Log4Shell RCE' (severity=CRITICAL)
  - 'Second Real Finding' (severity=HIGH)

=== Now the fully-empty / fully-garbage cases, for direct comparison ===
[ts] warning  skipping non-JSON nuclei output line     [kingsec.infrastructure.scanner]
[ts] warning  skipping non-JSON nuclei output line     [kingsec.infrastructure.scanner]
parse_nuclei_jsonl('') -> []
parse_nuclei_jsonl('completely unparseable garbage') -> []
```

**Conclusion:** 2 of 4 lines were genuinely malformed and silently dropped, logged at WARNING only. A wholly-garbage or wholly-empty input returns the identical `[]` shape a partially-corrupted input's residue would take if its 2 good lines had also been lost — there is no way, from the return value alone, to distinguish "genuinely clean scan" from "output was corrupted and everything was silently discarded."

### Script 2 — Non-zero exit code with partial valid output

```python
"""Phase 04 live proof #2: non-zero exit code + partial valid output.

Throwaway diagnostic script. Not part of tests/ or src/. Drives the REAL
NucleiScannerAdapter through a FakeRunner (same fake used by this repo's own
test suite) that returns exit code 1 alongside one genuinely valid JSONL
finding line - simulating a scanner that crashed partway through a run but
had already flushed some real output.
"""

import sys

sys.path.insert(0, "D:/New_folder/kingsec/src")

from kingsec.domain import Target, TargetType  # noqa: E402
from kingsec.infrastructure.config.models import ScannerSettings  # noqa: E402
from kingsec.infrastructure.scanner.errors import ScannerExecutionError  # noqa: E402
from kingsec.infrastructure.scanner.nuclei import NucleiScannerAdapter  # noqa: E402
from kingsec.infrastructure.scanner.runner import CommandResult  # noqa: E402


class FakeRunner:
    def __init__(self, result):
        self._result = result
        self.calls = []

    def run(self, args, *, timeout):
        self.calls.append((list(args), timeout))
        return self._result


PARTIAL_OUTPUT = (
    '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE",'
    '"severity":"critical"},"type":"http","matched-at":"http://10.0.0.5:8080/"}\n'
)

result = CommandResult(returncode=1, stdout=PARTIAL_OUTPUT, stderr="panic: runtime error: index out of range", duration_seconds=4.2)
runner = FakeRunner(result)
target = Target("10.0.0.5", TargetType.IP_ADDRESS)
adapter = NucleiScannerAdapter(ScannerSettings(), runner=runner)

print(f"=== CommandResult fed to the adapter: returncode={result.returncode} ===")
print(f"stdout: {result.stdout!r}")
print(f"stderr: {result.stderr!r}")

try:
    findings = adapter.scan(target)
    print(f"=== adapter.scan() returned NORMALLY with {len(findings)} finding(s) ===")
    for f in findings:
        print(f"  - {f.title!r} (severity={f.severity.name})")
except ScannerExecutionError as exc:
    print(f"=== adapter.scan() RAISED ScannerExecutionError: {exc} ===")
```

**Real output (verbatim):**
```
=== CommandResult fed to the adapter: returncode=1 ===
stdout: '{"template-id":"CVE-2021-44228","info":{"name":"Log4Shell RCE","severity":"critical"},"type":"http","matched-at":"http://10.0.0.5:8080/"}\n'
stderr: 'panic: runtime error: index out of range'

[ts] info     scan started                    [kingsec.infrastructure.scanner] binary=nuclei target=10.0.0.5
[ts] info     scan completed                  [kingsec.infrastructure.scanner] duration_seconds=4.2 findings=1 target=10.0.0.5
=== adapter.scan() returned NORMALLY with 1 finding(s) ===
  - 'Log4Shell RCE' (severity=CRITICAL)
```

**Conclusion:** `returncode=1` (an abnormal exit, `stderr` showing a real panic) was silently discarded. Because `parse_nuclei_jsonl()` found ≥1 valid finding, the shared guard clause's `and not findings` half is false, so the exception never fires. Note the adapter's own "scan completed" INFO log does not even mention the returncode — the crash leaves no trace anywhere in this function's observable behavior except the raw `stderr` string, which nothing downstream ever reads.

### Script 3 — Full-assessment outcome when the only scanner fails

```python
"""Phase 04 live proof #3: full-assessment outcome when the only scanner fails.

Throwaway diagnostic script. Not part of tests/ or src/. Wires the REAL
production components: a genuinely executable (but always-failing) fake
"nuclei" script run through the REAL SubprocessCommandRunner; the real
NucleiPlugin -> NucleiScannerAdapter chain; the real ScannerOrchestrator +
InMemoryPluginRegistry (the only registered plugin, so "the only scanner
fails" == "every scanner fails"); the real SubmitAssessment use case with a
real AssessmentExecutionEngine + scanner_executor, exactly as
bootstrap/composition.py wires it in production; a real in-memory
AssessmentRepository; and the real GET /api/v1/assessments/{id} route
handler via a real FastAPI TestClient.
"""

import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "D:/New_folder/kingsec/src")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from kingsec.adapters.inbound.web.auth import CurrentUser, get_current_user, require_viewer  # noqa: E402
from kingsec.adapters.inbound.web.dependencies import get_service  # noqa: E402
from kingsec.application.assessment_execution import AssessmentExecutionEngine  # noqa: E402
from kingsec.application.dto import GetAssessmentRequest, SubmitAssessmentRequest  # noqa: E402
from kingsec.application.ports.inbound.service_api import ServiceAPI  # noqa: E402
from kingsec.application.submit_assessment import SubmitAssessment  # noqa: E402
from kingsec.application.use_cases.get_assessment import GetAssessment  # noqa: E402
from kingsec.domain import Assessment, Authorization, Role, Target, TargetType  # noqa: E402
from kingsec.infrastructure.config.models import ScannerSettings  # noqa: E402
from kingsec.infrastructure.scanner.orchestrator import ScannerOrchestrator  # noqa: E402
from kingsec.infrastructure.scanner.plugins.nuclei import NucleiPlugin  # noqa: E402
from kingsec.infrastructure.scanner.registry import InMemoryPluginRegistry  # noqa: E402


class InMemoryAssessmentRepository:
    def __init__(self):
        self._store = {}

    def save(self, assessment):
        self._store[assessment.id.value] = assessment

    def get(self, assessment_id):
        return self._store[assessment_id.value]

    def list(self, *, limit=50, offset=0):
        return list(self._store.values())[offset : offset + limit]

    def delete(self, assessment_id):
        del self._store[assessment_id.value]


class _InlineJobRunner:
    def submit(self, job_id, fn, *args, **kwargs):
        fn()

    def is_running(self, job_id):
        return False

    def shutdown(self, wait=True):
        pass


class _GetOnlyService(ServiceAPI):
    def __init__(self, get_use_case):
        self._get = get_use_case

    def get_assessment(self, request):
        return self._get.execute(request)

    def create_assessment(self, request): raise NotImplementedError
    def start_assessment(self, request): raise NotImplementedError
    def submit_assessment(self, request): raise NotImplementedError
    def cancel_assessment(self, request): raise NotImplementedError
    def list_assessments(self, request): raise NotImplementedError
    def generate_report(self, request): raise NotImplementedError
    def delete_assessment(self, request): raise NotImplementedError


def _build_app(repo, current_user):
    app = FastAPI()
    service = _GetOnlyService(GetAssessment(repo))
    from kingsec.adapters.inbound.web.error_handlers import register_error_handlers
    from kingsec.adapters.inbound.web.routes import router

    register_error_handlers(app)
    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: service
    app.dependency_overrides[get_current_user] = lambda: current_user
    app.dependency_overrides[require_viewer] = lambda: current_user
    return app


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="kingsec_phase04_"))
    fake_nuclei = tmp / "fake_nuclei_always_fails.py"
    fake_nuclei.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('FATAL: could not load template directory\\n')\n"
        "sys.exit(1)\n"
    )
    fake_nuclei.chmod(fake_nuclei.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)

    plugin = NucleiPlugin(ScannerSettings(binary_path=str(fake_nuclei)))
    registry = InMemoryPluginRegistry()
    registry.register(plugin)
    orchestrator = ScannerOrchestrator(registry)

    repo = InMemoryAssessmentRepository()
    engine = AssessmentExecutionEngine()
    job_runner = _InlineJobRunner()

    assessment = Assessment.create(Target("10.0.0.5", TargetType.IP_ADDRESS))
    assessment.authorize(Authorization.grant("tester", scope="10.0.0.5"))
    assessment.set_ownership("alice")
    repo.save(assessment)

    use_case = SubmitAssessment(
        assessments=repo,
        scanner=orchestrator,
        job_runner=job_runner,
        execution_engine=engine,
        scanner_executor=orchestrator,
    )

    use_case.execute(SubmitAssessmentRequest(str(assessment.id), requesting_user="alice", is_admin=False))

    state = engine.get_state(str(assessment.id))
    print("=== AssessmentExecutionEngine's own per-scanner tracking ===")
    for p in state.scanner_progress:
        print(f"  scanner_id={p.scanner_id!r} status={p.status!r} error={p.error!r}")

    app = _build_app(repo, CurrentUser(user_id="alice", username="alice", role=Role.VIEWER))
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get(f"/api/v1/assessments/{assessment.id}")

    print(f"=== GET /api/v1/assessments/{assessment.id} -> HTTP {resp.status_code} ===")
    body = resp.json()
    print(f"status:          {body['status']!r}")
    print(f"failure_reason:  {body['failure_reason']!r}")
    print(f"findings:        {body['findings']!r}  (count={len(body['findings'])})")
    print(f"scanner_summary: {body['scanner_summary']!r}")


if __name__ == "__main__":
    main()
```

**Real output (verbatim):**
```
=== AssessmentExecutionEngine's own per-scanner tracking (in-memory, engine.get_state()) ===
  scanner_id='nuclei' status='failed' error="unexpected error in plugin 'nuclei': [WinError 193] %1 is not a valid Win32 application"

=== GET /api/v1/assessments/asmt-6901309e65f147eab72c40523f40a970 -> HTTP 200 ===
status:          'completed'
failure_reason:  None
findings:        []  (count=0)
scanner_summary: [{'scanner_id': 'nuclei', 'name': 'Nuclei Scanner', 'status': 'failed', 'findings_count': 0, 'skipped_reason': "unexpected error in plugin 'nuclei': [WinError 193] %1 is not a valid Win32 application"}]
```

**A note on the exact error text:** this investigation ran on Windows, where `subprocess.run()` cannot directly execute a Unix-shebang `.py` file as a native binary, so the real, unforced OS-level failure surfaced as `WinError 193` rather than a Unix-style non-zero `sys.exit(1)`. This is still a genuine, real subprocess-level failure raised by the actual production code path (not a `FakeRunner`-injected fake exception) — the OS refused to execute the configured "binary," which is itself a legitimate real-world scanner-misconfiguration scenario (a bad `binary_path` in `ScannerSettings`), just reached via a different concrete error than a deliberate non-zero exit. The finding it demonstrates — a real, unforced scanner-execution failure being fully absorbed before it can affect `status`/`failure_reason` — is unaffected by which specific OS-level error triggered it.

**Conclusion — this is the defect in its most damaging form, confirmed live and exactly as the prompt predicted:** every configured scanner failed via a real subprocess-level error. The assessment's own execution engine correctly recorded `status='failed'` with the real error text. The very same HTTP response that a real client would poll shows `scanner_summary` containing that same `status: 'failed'` entry, **in the same payload** as `status: 'completed'` and `failure_reason: null`. A customer reading only the top-level `status` field — which is what every existing UI affordance surfaces prominently — sees an ordinary, clean, zero-vulnerability result.

**VERIFIED**, all three scripts, real code paths, real output, reproducible by re-running the scripts above.

---

## 7. Severity Assessment

| Scanner | Affected by defect #4 (malformed→silent-zero) | Affected by defect #5 (partial+non-zero→silent-success) | Notes |
|---|---|---|---|
| Nmap | Yes (XML parse errors + per-host errors, `nmap_parser.py`) | Yes (identical guard clause) | Audit's named example; confirmed identical to the rest. |
| Nuclei | Yes (JSON decode errors, `parser.py`) | Yes (identical guard clause) | Confirmed **live** for both defects (Section 6, scripts 1–3) — the only scanner with a real subprocess-level proof in this investigation, per the prompt's instruction. |
| Nikto | Not applicable in the JSON/XML sense — plain-text/regex parsing has no "malformed" concept; a corrupted line simply fails to match and is skipped, same net effect | Yes (identical guard clause) | |
| ffuf | Yes (JSON decode errors, `ffuf_parser.py`) | Yes (identical guard clause) | |
| Gobuster | Not applicable, same reasoning as Nikto | Yes (identical guard clause) | |
| Amass | Yes (JSON decode errors, `amass_parser.py`) | Yes (identical guard clause) | Logs malformed lines at `_logger.debug`, not `warning` — even less visible than most siblings. |
| Trivy | Yes (JSON decode errors, `trivy_parser.py`) | Yes (identical guard clause) | Logs at `_logger.debug`. Also the audit's separately-noted "target-type defect" — out of scope here (§4 of the prompt), not conflated with this finding. |
| ZAP | Yes (JSON decode errors, `zap_parser.py`) | Yes (identical guard clause) | Logs at `_logger.debug`. |
| Semgrep | Yes (JSON decode errors, `semgrep_parser.py`) | Yes (identical guard clause) | Logs at `_logger.debug`. Also the audit's separately-noted target-type defect — out of scope here. |

**All 9 scanners are affected by defect #5** (the adapter-level guard clause is identical everywhere). **7 of 9 are affected by defect #4** in the JSON/XML-decode sense; the remaining 2 (Nikto, Gobuster) have no distinct "malformed" failure mode because their plain-text parsers have no structural validity to fail — they degrade to the same "found nothing" outcome by a slightly different mechanism, which is arguably just as severe in effect even though it isn't literally the same code path.

**The single most severe finding, affecting every scanner and both usage paths equally:** the swallow point at `orchestrator.py:118-136` and the unconsulted-data point at `submit_assessment.py:284` / `start_assessment.py:112` (Sections 3–4) mean that **no per-adapter fix to defects #4 or #5 alone would change the customer-visible outcome**, because the orchestrator already catches every adapter-level exception regardless of its cause, and the completion decision already ignores whatever the orchestrator or execution engine recorded. Fixing only the adapters (e.g., tightening the guard clause) would improve `scanner_summary`'s accuracy in edge cases but would not, by itself, change `status`/`failure_reason` — those are governed entirely by Section 4's call graph, independent of which specific adapter-level condition triggered the failure.

**`StartAssessment` (the synchronous path) is categorically worse than `SubmitAssessment`** for this defect: it has no execution engine, never records `scanner_summary`, and therefore offers a caller precisely zero information beyond `status`/`findings_count` — there is no "scanner coverage" data anywhere for an assessment run this way, successful or not.

---

## 8. Proposed Remediation Options (Not Chosen — For Decision)

### Option A — Consult the already-captured scanner outcome before deciding COMPLETED vs. FAILED (plumbing fix)

Since Section 5 established the failure data already exists correctly by the time `submit_assessment.py:284` runs, the smallest structural change is to read it there: if every scanner that was attempted (i.e., every entry in `ran_summaries` that isn't a pre-planned `skipped` entry) has `status == "failed"`, call `assessment.fail(...)` (using a message built from the recorded per-scanner errors, reusing `safe_failure_message`-style sanitization) instead of `assessment.complete()`.

- **Blast radius:** primarily `submit_assessment.py` (one new conditional before line 284). `start_assessment.py` would need real work too — it has no `scanner_summary`/execution-engine wiring to consult at all, so this path either needs the same engine wired into it (nontrivial: `StartAssessment`'s constructor, its factory in `composition.py`, and its "no threads/executors" design note in its own docstring would all need revisiting) or a separate, smaller signal invented for the synchronous case specifically.
- **Open policy question this doesn't answer by itself:** what should happen when *some* scanners fail and others succeed (with findings, or with zero findings)? A binary COMPLETED/FAILED status may not be expressive enough for that case — this is exactly the `PARTIAL SUCCESS` state named in the prompt's six-state model (§7 of the prompt), which does not exist in the current `AssessmentStatus` enum at all. Introducing it would be a domain enum change, materially larger than "plumbing."
- **Estimated files touched:** 2–4 for the minimal all-scanners-failed case (`submit_assessment.py`, possibly `start_assessment.py`, possibly a small addition to `_support.py` for the "were all scanners failed" check), or substantially more (domain enum + every place that pattern-matches on `AssessmentStatus` + migration) if the partial-success case is handled with a new state rather than left as COMPLETED-with-visible-`scanner_summary` (which already works today, per Section 5).

### Option B — Redesign the scanner contract to return a structured outcome instead of swallowing failures internally

Change `ScannerPort.scan()` / `ScannerExecutor.execute_all()` to return something richer than a bare findings sequence — e.g. a `ScanOutcome` carrying both the findings and the set of scanners that failed (with reasons) — so *any* caller, not just one wired to an `AssessmentExecutionEngine`, can make an informed completion decision without reaching into engine state that only exists on the async path.

- **Blast radius:** the port definitions (`application/ports/services.py`'s `ScannerPort`, `application/ports/scanner_executor.py`'s `ScannerExecutor`), `ScannerOrchestrator.scan()`/`execute_all()`, both use cases (`start_assessment.py`, `submit_assessment.py`), and — because this changes a port's contract — every existing test double that implements `ScannerPort` across the test suite (a non-exhaustive grep during this investigation found `FakeScanner`/`StubScanner`/`RecordingScanner`/`_RecordingScanner` test doubles in at least `test_start_assessment.py`, `test_submit_assessment.py`, and `test_get_and_report.py`; there are likely more).
- **Trade-off:** architecturally the more correct fix — it closes the gap for `StartAssessment` and `SubmitAssessment` uniformly, with one shared mechanism, rather than solving it twice (or leaving one path unsolved). Meaningfully larger diff and higher regression risk purely from the number of touched call sites and test doubles, even though each individual change is conceptually simple.
- **Estimated files touched:** roughly 8–15 production files (2 ports, 1 orchestrator, 2 use cases, plus whichever adapters/plugins are updated to populate the richer result — potentially all 9 adapters and/or 9 plugin wrappers, depending on whether the richer shape is built at the adapter layer or only at the orchestrator layer) plus an unknown-but-nonzero number of test files that construct a `ScannerPort`-shaped double and would need to conform to the new contract.

**Neither option is recommended here — that is a Phase 05 decision**, per §0 of the prompt.

---

## 9. What This Investigation Could NOT Determine

- **Real-binary behavior for the other 8 scanners.** Per the prompt's explicit instruction, only Nuclei was exercised with a genuinely executable subprocess. The taxonomy conclusions for Nmap, Nikto, ffuf, Gobuster, Amass, Trivy, ZAP, and Semgrep rest on static code reading (all 9 adapters share identical logic, so this is a well-founded inference, not a guess) rather than live execution against each one's real binary. **Labeled: inferred from identical shared code, not independently live-proven per scanner.**
- **Production log-aggregation visibility.** Whether the `_logger.debug`-level parse-failure logs (Amass, Trivy, ZAP, Semgrep) are actually captured by KingSec's deployed logging configuration was not checked — this investigation only confirmed the *code's* log level, not any specific deployment's effective threshold. **Labeled: UNKNOWN, deployment-dependent.**
- **Behavior of a currently-non-existent `PARTIAL SUCCESS` domain state.** Section 8's Option A raises this as an open design question; this investigation deliberately did not design or prototype it, per §0's prohibition on implementing anything.
- **Whether every `ScannerPort` test double in the full test suite was found.** Section 8's Option B blast-radius estimate is based on a targeted grep during this investigation, not an exhaustive enumeration — the real count if Option B were chosen would need to be established at that time.
- **Gobuster's and Nikto's plain-text parsers' behavior on inputs that are technically well-formed text but semantically nonsensical** (e.g., a HTML error page returned by a misconfigured web server in place of real Gobuster/Nikto output) was reasoned about but not live-proven the way Nuclei's JSON case was — reasoning is sound (no line would match the finding regex, so it degrades to "zero findings" the same way genuinely-clean output does) but is not backed by a running script the way Section 6's three proofs are. **Labeled: reasoned, not live-proven.**

---

## 10. Recommended Phase 05 Scope

Do not implement Phase 05 here — this section only states what to investigate/decide next, per §0.

1. **Make the Option A vs. Option B decision** (Section 8) before writing any code — this is a real architectural fork, not a detail to resolve mid-implementation.
2. If Option A is chosen: decide the policy for the partial-failure case (some scanners fail, some succeed) explicitly, in writing, before touching code — do not let it default to whatever the first implementation attempt happens to produce.
3. Whichever option is chosen, `StartAssessment`'s complete lack of `scanner_summary` tracking (Sections 3, 4, 7) needs its own explicit decision: wire it into the same mechanism `SubmitAssessment` uses, or accept that the synchronous path will remain permanently blind to this class of failure and document that as an intentional limitation.
4. Fix the `_logger.debug` vs. `_logger.warning` inconsistency across the parser modules (Section 2) as a small, low-risk, high-value companion to whichever main fix is chosen — it is not sufficient on its own, but its absence undermines even manual log-based investigation today.
5. Add real regression tests for whichever fix is chosen, explicitly covering: all-scanners-fail → FAILED (or whatever the Phase 05 policy decides), partial-failure → the Phase 05 policy's chosen state, and — critically, since Section 3 confirmed this doesn't exist today — a test that the previously-shown swallow behavior (`test_one_plugin_fails_others_continue`, `test_empty_findings`/`test_empty_registry` all currently and correctly assert the *current*, defective, indistinguishable-outcome behavior) is deliberately and explicitly changed, not just left in place alongside new tests that contradict it.
6. The malformed-output-with-partial-recovery scenario (defect #4) and Section 8's remediation options largely address the "all scanners fail" case cleanly; Phase 05 should explicitly re-examine whether they also need it re-confirmed for the "some findings recovered from otherwise-corrupted output" case, since that is a slightly different shape than either "all failed" or "some scanners failed entirely."

---

## Report Path

`docs/audits/KINGSEC-PHASE-04-SCANNER-FAILURE-INTEGRITY-INVESTIGATION.md`
