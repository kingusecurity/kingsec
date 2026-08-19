# KingSec Current-State Engineering Audit

**Date:** 2026-08-19
**Scope:** Full repository at `D:\New_folder\kingsec`, HEAD commit `4f4b666`
**Method:** Direct repository inspection, real test-suite execution, and code-level tracing. No prior documentation, changelog, README, or session history was trusted without independent verification against the actual source. Where documentation and implementation conflict, implementation wins and the conflict is recorded.

Every claim below is labeled: **VERIFIED** (directly confirmed by reading code and/or running it), **OBSERVED** (seen in code, not independently executed), **NOT VERIFIED** (checked for, no evidence found either way), **UNKNOWN** (out of scope or inconclusive), **INFERRED**, **DOCUMENTED ONLY**, or **BROKEN**.

---

## Executive Summary

### What is KingSec?

A locally-hosted, single-tenant, AI-augmented web application (FastAPI backend + React/TypeScript frontend) that orchestrates 9 open-source security scanners against a user-supplied target, converts their raw output into a persisted domain "Finding" model, and renders PDF/HTML assessment reports. It ships as a Docker image or a Python wheel, uses SQLite by default, and implements its own RBAC/JWT authentication and an offline Ed25519 license-signing scheme.

### What is actually implemented?

A genuinely substantial system, not a prototype: a real hexagonal-architecture backend (domain layer has zero framework imports, application layer has zero infrastructure imports — **VERIFIED** by grep), 9 real scanner adapters with real subprocess execution and real per-scanner output parsers, a real PDF/HTML report renderer, a real 56-route React frontend with ~89% of interactive elements wired to working endpoints, real JWT+MFA authentication with role-based route guards, and a Docker packaging pipeline that was independently proven portable this session (built, exported, wiped from a clean Docker cache, reloaded, and re-verified healthy with real HTTP responses).

### What scanners actually work?

All 9 declared scanners (Nmap, Nuclei, Nikto, ffuf, Gobuster, Amass, Trivy, ZAP, Semgrep) have real adapter classes, real non-shell subprocess execution, real output parsers, and are wired into the DI container at application startup — **VERIFIED**, not documentation-only. However, only **Nuclei** has a genuine subprocess-level integration test; the other 8 are verified only against a `FakeRunner` test double, never a real binary, in this repository's test suite. **Trivy and Semgrep cannot currently be driven with realistic input** — see "Actual Target Types" below.

### What targets can it actually scan?

Hostname, IPv4/IPv6 address, URL, and CIDR network — **VERIFIED** via the domain `Target` value object and its validators. There is **no** target type for a container image or a local source path, despite Trivy's and Semgrep's real CLI invocations requiring exactly that. Both currently declare a `HOSTNAME` capability as a workaround, which is semantically wrong for their real usage and unverified against any realistic value (**BROKEN** for realistic use, confirmed live by constructing representative `Target` objects and observing `InvariantViolation`).

### Does an assessment currently complete successfully?

Yes, for the common case. CREATE → AUTHORIZE → RUNNING → COMPLETED is a real, enforced, persisted state machine — **VERIFIED**.

### Does zero-findings work correctly?

Partially. It is rendered honestly and explicitly in the PDF/HTML report (**VERIFIED**), but the assessment's own status field cannot distinguish a genuinely clean scan from a scanner that silently failed to parse malformed output — both produce a `COMPLETED` assessment with zero findings and no error anywhere (**BROKEN**, proven by code trace).

### How trustworthy are the findings?

Severity and CVSS values are genuinely extracted from scanner output, never fabricated or estimated by KingSec (**VERIFIED**) — this is a real strength. But there is **no finding deduplication anywhere in the codebase** (**CONFIRMED MISSING**): re-running the same scan against the same target will pile up duplicate findings indefinitely. There is also no queryable scanner-attribution field on a Finding — "which scanner produced this" is only recoverable by string-parsing free-text evidence.

### How trustworthy are the reports?

This is the strongest subsystem in the product. All findings are included with no truncation, severity totals are computed once and read from a single source by both the report and its metadata endpoint (cannot diverge from each other), evidence and remediation are genuinely present with honest "not available" fallbacks rather than fabrication, and scanner failures are represented, not hidden — all **VERIFIED**. The real gaps: only PDF and HTML exist (README/CHANGELOG claims of JSON/CSV/Markdown/SARIF export are **CONTRADICTED** by code), and a generated report is an immutable snapshot that can silently drift from the live assessment view (e.g., after a finding is later marked false-positive) with no staleness indicator.

### What are the biggest current defects?

1. **A `FAILED` assessment shows zero error text through the one endpoint every real client uses to check on it** — the domain and database layers capture the failure reason correctly, but it is dropped at the DTO boundary (`AssessmentView.from_domain`) before it ever reaches the API response. **PROVEN**, code-level.
2. **A confirmed High-severity authorization gap**: `worker_routes.py` has zero role/authorization check on any of its routes — any authenticated user, including a self-registered default-role Viewer, can register fake workers, forge heartbeats, and delete real distributed-worker nodes.
3. Malformed scanner output is silently indistinguishable from a clean scan (parser catches the parse error, logs it, and returns an empty list — no error propagates).
4. Zero finding deduplication.
5. Trivy and Semgrep are effectively non-functional against realistic input via the current domain model.

### Is it ready for external testers?

Conditionally. The core create→scan→report pipeline genuinely works for the scanners with matching target types. But testers will hit unexplained "Failed" assessments with no diagnostic text, and the worker-management authorization gap should be closed before any external accounts are issued.

### Is it ready for paying customers?

**No.** A confirmed authorization bypass on a real feature, a proven error-visibility defect in the core product loop, two scanners that cannot be used as advertised, and multiple confirmed contradictions between documented capability claims ("multi-format reports," "production-ready... full security hardening") and actual code are release blockers for a security product.

---

## Repository Inventory

**Languages/frameworks:** Python ≥3.11 (backend: FastAPI, SQLAlchemy 2, Alembic, Pydantic v2, structlog, WeasyPrint/ReportLab, `cryptography` for Ed25519 license signing, Argon2, PyJWT); TypeScript/React 19.2 (frontend: Vite 8, TanStack Query/Table, Zustand, Tailwind, Recharts, oxlint, Vitest + Playwright). Build backend: hatchling.

**Entry points:** `src/kingsec/__main__.py` (composes and runs the app via uvicorn). `pyproject.toml [project.scripts]`: `kingsec` (run server), `kingsec-migrate` (Alembic), `kingsec-bootstrap`. `tools/issue_license.py` (offline license-signing CLI, holds the private key, never imported by the running app — **VERIFIED**).

**Persistence:** SQLite via SQLAlchemy 2 ORM, Alembic migrations at `src/kingsec/alembic/`. 34 migration files, of which **9 are named `*__no_changes.py`** — a recurring test-pollution artifact (see "Current Defects"). Two Unit-of-Work implementations coexist by documented design (`SqlAlchemyUnitOfWork` "legacy" and `SQLAlchemyUnitOfWork` "new," Phase 7.4) — **OBSERVED**, self-aware in its own docstring, not accidental duplication, but a real ongoing-migration-debt signal.

**Docker:** 3-stage `Dockerfile` (Node frontend build → Python wheel build with the frontend bundled in → minimal non-root runtime). `docker-compose.yml` hardens the container (`read_only: true`, `no-new-privileges`, no host mounts, no Docker socket, loopback-only host bind) — **VERIFIED SAFE**.

**CI/CD:** `.github/workflows/ci.yml` runs a real Python 3.11/3.12/3.13 matrix (ruff, mypy, import-linter, bandit, pip-audit, pytest with coverage) and a real frontend job (oxlint, `tsc -b --noEmit`, vitest). **Playwright e2e tests are never invoked in CI** despite existing in `package.json` (**CONFIRMED gap** — the `test:e2e` script has no CI job calling it). `release.yml` builds and quality-gates on version tags, publishes a GitHub Release only (proprietary license, no PyPI).

**Counts:** ~614–616 backend Python source files, 233 backend test files, 266 frontend TS/TSX files. Backend `src/` ≈ 74,000 LOC, tests ≈ 40,000 LOC, frontend `src/` ≈ 27,000 LOC. **2,725 test functions** defined; **2,718 collected and run** in this audit (see Test Suite Assessment). TODO/FIXME/XXX markers: **effectively zero** — the one repo-wide grep hit is a form placeholder string (`"CVE-XXXX-XXXXX"`), not a real marker.

**Dead code and duplication found (VERIFIED):**
- `src/kingsec/interfaces/api/` contains **only compiled `.pyc` bytecode**, zero `.py` source, zero importers anywhere — forensic evidence of a fully-removed earlier API layer, superseded by the current `adapters/inbound/web/`.
- **Two independent license-key parsing implementations.** `application/services/license_key_codec.py` (Ed25519, `KSL1.` format) is the live one. `infrastructure/licensing/parser.py` (HMAC-SHA256, `KS-` format, includes machine-fingerprint binding with no counterpart in the live scheme) is **confirmed fully dead** — referenced only by its own re-export and its own isolated test.
- **Two disconnected Finding/Report schemas.** The live pipeline uses `FindingORM`/`ReportORM` (tables `findings`/`reports`). A second, better-designed schema — `FindingModel`/`ReportModel` (tables `scan_findings`/`scan_reports`), which actually has a `scanner` attribution column and an `asset_id` FK that the live schema lacks — exists, has its own mappers and repository, but is **never populated by the real assessment pipeline**. A superior design sits unused next to the one that's actually missing scanner attribution.
- `LegacyAssessmentRepository`/`LegacyReportRepository` are misleadingly named — despite "Legacy," these **are** the live, production-wired repository implementations (**VERIFIED** via `bootstrap/composition.py`/`provisioning.py`). The naming actively misdirects anyone auditing which implementation is real.

---

## Actual Architecture

Traced one full real request (`POST /api/v1/assessments`) end-to-end through every layer:

```
adapters/inbound/web/routes.py:386-407   (FastAPI handler, builds DTO from Pydantic body)
        ↓
application/service_api.py:63-64          (thin facade)
        ↓
application/use_cases/create_assessment.py:22-93   (orchestrates domain objects, depends only on abstract ports)
        ↓
domain (Assessment.create, Authorization.grant, AuditEntry)   (pure, no I/O)
        ↓
infrastructure/persistence/_legacy_repositories.py:152-231   (concrete port implementation — SQLAlchemy)
        ↓
bootstrap/composition.py:566-573   (DI wiring binds the abstract port to the concrete implementation)
```

**Dependency direction — VERIFIED respected for the traced path and repo-wide via grep:** `domain/` contains zero imports of `application`, `adapters`, `infrastructure`, `fastapi`, `pydantic`, or `sqlite3` (grep-confirmed, zero matches). `application/` contains zero imports of `adapters`, `infrastructure`, or web/HTTP frameworks (grep-confirmed, zero matches). The CI-declared `import-linter` gate that's supposed to enforce this automatically could not be executed in this audit (the `lint-imports` tool is not installed in this environment's virtualenv) — the grep result is a manual substitute for that gate, not proof the CI job itself currently passes.

Major layers, each independently confirmed by reading representative files, not inferred from directory names:
- **`domain/`** (41 files) — pure dataclasses/enums/aggregates.
- **`application/`** — use cases, abstract ports, feature submodules (AI, compliance, distributed, playbooks, plugin SDK, threat intelligence).
- **`infrastructure/`** (largest layer, 30+ submodules) — persistence, scanner adapters, licensing, auth/MFA, secrets, reporting, notifications, queue, worker.
- **`adapters/inbound/web/`** — ~35 FastAPI route files, app factory, SPA static-file serving.
- **`bootstrap/`** — the composition root; every DI binding lives in `composition.py`.

---

## Actual Scanner Capabilities

Architecture: a flat adapter module per scanner (real subprocess call + parsing) wrapped by a thin plugin adapter (capability metadata + `is_available()`). All subprocess execution funnels through one shared, non-shell `SubprocessCommandRunner` (`infrastructure/scanner/runner.py`, `shell=False`, argument list, mandatory timeout). `register_scanner()` wires all 9 into the DI container at real application startup (`bootstrap/composition.py`) — **VERIFIED live-wired, not dead code**.

| Scanner | Integrated? | Binary present? | Callable? | Output parsed? | Findings generated? | Verified by test? | Evidence |
|---|---|---|---|---|---|---|---|
| **Nuclei** | Yes | Real CLI, on PATH | Yes | Yes (real JSONL parser) | Yes | **Yes — the only one with a real-subprocess, DB-persisted integration test** | `infrastructure/scanner/nuclei.py`, `tests/integration/scanner/test_nuclei_integration.py` |
| Nmap | Yes | Real CLI | Yes | Yes (real XML parser, 180 lines) | Yes | Unit only (`FakeRunner`) | `nmap.py`, `nmap_parser.py`, `test_nmap_plugin.py` |
| Nikto | Yes | Real CLI | Yes | Yes | Yes | Unit only | `nikto.py`, `nikto_parser.py` |
| ffuf | Yes | Real CLI | Yes | Yes | Yes | Unit only | `ffuf.py` |
| Gobuster | Yes | Real CLI | Yes | Yes | Yes | Unit only | `gobuster.py` |
| Amass | Yes | Real CLI | Yes | Yes (real severity heuristics) | Yes | Unit only | `amass.py`, `amass_parser.py` |
| Trivy | Yes (code) | Real CLI | **Yes as coded, but see target-type gap below** | Yes (211-line parser, real CVSS-source logic) | Yes | Unit only, using a hard-coded fake hostname, not realistic input | `trivy.py`, `trivy_parser.py` |
| ZAP | Yes | Invoked as `"zap"` on PATH — not independently confirmed to match the real OWASP ZAP CLI distribution in a deployed environment | Yes as coded | Yes | Yes | Unit only | `zap.py` |
| Semgrep | Yes (code) | Real CLI | **Yes as coded, but see target-type gap below** | Yes (159-line parser, extracts CVE/CWE) | Yes | Unit only, using a hard-coded fake hostname | `semgrep.py`, `semgrep_parser.py` |

**Classification:** Nmap/Nuclei/Nikto/ffuf/Gobuster/Amass/ZAP = **IMPLEMENTED+VERIFIED** at the unit level (real code path, real parser, real test assertions), **IMPLEMENTED+NOT VERIFIED** against a real binary except Nuclei. Trivy/Semgrep = **PARTIALLY IMPLEMENTED / effectively BROKEN for realistic use** — see below.

**The Trivy/Semgrep target-type defect (BROKEN, live-confirmed):** both declare `target_types=frozenset({TargetType.HOSTNAME})`, but their real CLI invocation needs a filesystem path (`semgrep scan --json <path>`) or a container-image reference (`trivy fs`/`image --format json <target>`). The domain `Target` value object's hostname validator rejects both a real path (`/app/src`) and a real image reference (`nginx:latest`, `ghcr.io/foo/bar:tag`) with `InvariantViolation` — confirmed by direct construction. Their own unit tests avoid this entirely by hard-coding `Target("example.com", HOSTNAME)`, a value that passes validation but is meaningless input for either tool. **There is no code path anywhere in the domain layer that can construct a `Target` carrying an image reference or a filesystem path.**

---

## Actual Target Types

Domain model: `src/kingsec/domain/target.py`. `TargetType` has exactly four members: `HOSTNAME`, `IP_ADDRESS`, `URL`, `NETWORK`. There is no type for source repository, local source, container image, or "API endpoint" — those exist only in scanner docstrings/comments, never as a constructible domain concept.

| Target type | API accepts? | Validated? | Understood by a scanner? | Actually executed? | Result pipeline handles it? | Tested? |
|---|---|---|---|---|---|---|
| IPv4 address | Yes | Yes (`ipaddress.ip_address`) | Yes (Nmap, Nuclei) | Yes | Yes | Yes — real integration test |
| IPv6 address | Yes (no format-specific rejection) | Yes | Not demonstrated anywhere | **NOT VERIFIED** | **NOT VERIFIED** | **No test found** |
| Hostname | Yes | Yes (RFC hostname regex) | Yes (7 of 9 scanners) | Partially — several adapters build URL-shaped CLI args from a bare hostname with no scheme, untested against real binaries | Generic | Unit only |
| URL | Yes | Yes (scheme+netloc check) | Yes (ZAP, Nikto, ffuf, Gobuster) | Yes, code-level | Generic | Unit tested |
| CIDR/Network | Yes | Yes (`ipaddress.ip_network`) | Only Nmap declares it | **NOT VERIFIED** — no test constructs and runs a NETWORK target | **NOT VERIFIED** | **No test found** |
| Container image | **No — not a type at all** | N/A | Trivy needs it, declares HOSTNAME instead | **No** — fails domain validation | N/A | No |
| Local source/repo | **No — not a type at all** | N/A | Semgrep needs it, declares HOSTNAME instead | **No** — fails domain validation | N/A | No |
| API endpoint (distinct type) | No — would just be a URL | N/A | N/A | N/A | N/A | N/A |

---

## Assessment Lifecycle

Status enum (`domain/enums.py`): `DRAFT → AUTHORIZED → RUNNING → {COMPLETED, CANCELLED, FAILED}`. Legal transitions are enforced by a real state machine (`domain/assessment.py`, `_transition_to`), not ad hoc field writes — **VERIFIED**.

- **CREATE**: `Assessment.create()` → `DRAFT`.
- **AUTHORIZE**: happens synchronously inside the same use case (`create_assessment.py`) — there is no separate "authorize later" step; this is by design, stated in the code's own docstring, not an oversight.
- **RUNNING**: Two code paths exist — a synchronous `StartAssessment` use case, and the real async path `SubmitAssessment` used by the actual HTTP route. **`StartAssessment` is dead code from the HTTP surface's perspective** — confirmed by repo-wide grep, no route calls it, only `submit_assessment` is reachable via `POST /assessments/{id}/start`.
- **Scanner execution**: `ScannerOrchestrator.execute_all()` resolves plugins from the registry, calls `health_check()` + `scan()` per plugin, and **catches and logs per-plugin failures without re-raising** — one scanner failing does not stop the others, and does not fail the assessment. This is intentional and reasonable, but means a scanner-level failure never becomes visible as an assessment-level exception.
- **COMPLETE**: unconditional once the scan loop finishes — **there is no check that any scanner actually succeeded.** Zero findings and "every scanner failed" both reach the identical `COMPLETED` state.
- **FAIL**: one real code path (an outer `except Exception` around the whole execution, covering plan-level errors like "no scanner installed for a *required* capability," or unexpected bookkeeping errors) — ordinary per-scanner failures do not reach this path at all (they're caught one level down, per above).

**Exception handling — mixed, one confirmed silent swallow:** the *dead* synchronous `StartAssessment.execute()`'s AI-enrichment failure handler is `except Exception: return` with **no log call at all** (comment claims "the adapter is responsible for logging," which isn't true at that call site). The *live* async path's equivalent handler does log. Since the swallowing one is dead code, its practical impact today is low, but it is a real landmine if that path is ever reactivated.

**Missing binary / non-zero exit / timeout / malformed output — traced individually:**
- Missing binary → `FileNotFoundError` → wrapped, logged, that scanner marked failed in its own summary, **other scanners and the assessment overall still complete**. A *required*-scanner-missing case (pre-execution planning) does correctly fail the whole assessment — **VERIFIED** by an existing unit test.
- Non-zero exit with **some** findings still parsed → **no error raised at all** (Nmap: `if returncode != 0 and not findings: raise` — the `and not findings` means a degraded/partial run is silently treated as a full success).
- Timeout → real `subprocess.run(timeout=...)` mechanism, not undefined behavior — **VERIFIED**.
- Malformed/unparseable scanner output → parser catches the parse error, **logs it, and returns an empty findings list without raising**. Combined with the non-zero-exit behavior above, a scan that exits 0 with garbage output produces zero findings with no error anywhere in the system — **indistinguishable from a genuinely clean scan.** This is a real, demonstrable detection-reliability gap.

---

## Assessment Failure Investigation

**The FAILED-visibility hypothesis is CONFIRMED TRUE, with the exact code-level cause identified — not assumed, traced.**

The failure reason **is** correctly captured at the domain and database layers: `Assessment.fail(reason)` stores it, `FindingORM`'s sibling `AssessmentORM.failure_reason` column persists it, and mappers round-trip it correctly. It is even partially exposed through a *separate*, in-memory, non-persistent execution-tracking endpoint (`GET /assessments/{id}/execution/status`) — but only while the assessment is still `running`/`pending`.

**The break is at the DTO boundary.** `application/dto.py`'s `AssessmentView.from_domain()` maps every domain field onto the view **except `failure_reason`** — the field doesn't exist on `AssessmentView` at all. The HTTP schema (`AssessmentResponse`, `extra="forbid"`) inherits the same omission. `GET /assessments/{id}` — the one endpoint every client actually polls, including after the assessment reaches a terminal state — therefore returns a bare `"status": "failed"` with zero explanatory text, permanently, for every failed assessment.

The frontend confirms the user-visible consequence: the only UI component that ever renders an error message (`ExecutionProgressPanel`) is conditionally rendered **only while the assessment is `running` or `pending`** — it disappears the moment the assessment reaches `FAILED`, at exactly the moment a user would want to see why. A user sees a red "Failed" badge and nothing else.

No test anywhere in the 233-file test suite asserts that the DTO or the HTTP response carries a failure reason — the gap is untested as well as unfixed.

---

## Findings Pipeline

Parsing is real per-scanner, with malformed records logged and dropped rather than fatal. Severity mapping is table-driven per scanner (not shared/generic — each parser duplicates its own map) and is always scanner-reported, never computed by KingSec; unknown/unrecognized severity strings silently default to the *lowest* tier (`INFORMATIONAL`), which is a conservative-in-the-wrong-direction default worth noting. CVSS scores are genuinely extracted from real scanner fields (Nuclei/Trivy only) and never fabricated — confirmed by reading the extraction code and the domain's own validation guard.

Evidence is a formatted reconstruction of real scanner fields (not a byte-for-byte raw snippet), traceable but not verbatim.

**Deduplication is confirmed missing.** The only existing check rejects an *exact* `FindingId` collision, but every finding gets a freshly generated UUID, so that check can never fire in practice. There is no content-based fingerprint anywhere. Findings from multiple scanners, or from re-running the same scan, simply accumulate forever.

**Scanner attribution is not a structured, queryable field** on the live `Finding`/`FindingORM` — it exists only as free text baked into the evidence summary string (e.g., "Matched by Nuclei template..."). The disconnected `FindingModel`/`scan_findings` schema *does* have a proper `scanner` column, but nothing in the live pipeline writes to it (see "Repository Inventory" duplication findings).

`ExecutionPhase.CORRELATING` — a real, user-visible progress-bar state — has zero logic executing between it and the next phase. It is cosmetic, not a real correlation stage.

---

## Risk & Intelligence

| Capability | Status | Notes |
|---|---|---|
| Severity assignment | Implemented | Scanner-reported, translated via per-scanner table |
| CVSS scoring | Implemented, real | Genuine extraction, never estimated; only Nuclei/Trivy |
| Confidence scoring | Partial/narrow | Only the AI's self-reported confidence in its own explanatory text; no per-finding true/false-positive confidence |
| Asset criticality | Partial / effectively designed-only | Real formula exists, but its inputs (`critical_findings`/`high_findings`/`open_findings`) are taken directly from a POST body, not derived from actual finding data tied to the asset |
| Exploitability scoring | Designed-only relative to findings | A real formula exists in a standalone CVE/threat-intel subsystem, never fed a real Finding's CVE ID |
| Exposure assessment | Designed-only | Rich domain model exists, never referenced by the assessment/finding pipeline |
| Correlation | **Broken/cosmetic only** | The "Correlating" phase executes no logic |
| Deduplication | **Confirmed missing** | See Findings Pipeline |
| Attack-path analysis | Missing | No code found |
| Overall risk scoring | Implemented, real | `100 − Σ(severity penalty × count)`, the formula actually shown in reports; a second, unrelated formula exists in the disconnected CVE subsystem |
| Prioritization | Partial | Pure severity ordering only, no weighting by exploitability/criticality/exposure |
| Business impact | Partial, text-only | AI-generated prose per critical/high finding, with an honest "not available" fallback; not a quantified metric |
| AI enrichment | **Implemented, real** | Real HTTP calls to configured providers (OpenAI-compatible/Anthropic/Gemini). **Severity is explicitly and permanently preserved from the scanner** — the code contains an explicit comment ("Never trust the model's severity") and hard-sets `priority=finding.severity` regardless of AI output. This is a deliberate, verified, and good design decision. |

---

## Reporting

Only **PDF and HTML** exist — confirmed by reading the report adapter's format registry and by a repo-wide grep for SARIF/CSV finding zero non-test hits. All findings are included with no truncation or slicing. Severity totals are computed once, from all findings, and read from that single stored value by both the report body and its metadata endpoint — **they cannot diverge from each other by construction**. Evidence is rendered in full inside the report, not summarized or truncated. Remediation uses a real fallback chain (AI/analyst text → a narrow curated table → an honest "no guidance available"), never fabricating advice for an unmatched finding type. Limitations/scope caveats are unusually thorough, including a conditional (not blanket) CVE/CVSS disclaimer that's accurate about which findings do and don't carry that data. Scanner failures and skipped scanners are represented in a dedicated "Scanner Coverage" section, not hidden. A zero-findings assessment renders an honest positive-empty state, not a broken-looking blank template.

**Confirmed divergence risk:** a generated report is an immutable snapshot written once (`GenerateReport.execute` → `reports.save(report)`). The live `GET /assessments/{id}` view reflects real-time finding-status changes (e.g., a finding later marked false-positive); the already-generated report/its metadata endpoint do not, and carry no staleness indicator. Only manual regeneration resyncs them.

---

## API Surface

34 routers registered under `/api/v1` (`adapters/inbound/web/versioning.py`). A representative sample across every major resource area was inspected in depth (see Evidence Appendix for the full table). Key findings:

**Routes confirmed to have genuinely no auth dependency** (by design, not a bug): `/health`, `/healthz/live`, `/healthz/ready`, `/auth/login`, `/auth/register`, `/auth/refresh`, `/sessions/refresh`. Every other route initially flagged by an automated sweep turned out to be a false positive on manual inspection (auth enforced via router-level dependencies or an indirect service getter).

**Two confirmed authorization gaps (the most important finding of this entire audit):**
- **High — `worker_routes.py`**: every route (`register`, `heartbeat`, list, get, **delete**) depends only on `get_current_user` — there is no role/admin check anywhere in the file. Any authenticated user, including a brand-new self-registered default-role Viewer, can register fake distributed workers, forge heartbeats, and **delete any real worker by ID**.
- **Medium — `distributed_routes.py`**: the mutating queue endpoints (`retry`, `cancel`, `dead-letter/requeue`) also depend only on `get_current_user`, with no role check — inconsistent with the sibling `queue_routes.py` implementation under the same URL prefix, which correctly requires admin on its equivalent mutating endpoints. The inconsistency between two parallel implementations of the same concept is itself evidence this is a gap, not intent.

**Additional confirmed findings (lower severity):**
- Low — username/email enumeration on `/auth/register` via distinguishable error messages, directly contradicting that use case's own docstring ("rejected with generic messages"). Rate-limited, not blocked.
- Low — the unauthenticated `/healthz/ready` probe reflects raw exception text on a DB/filesystem check failure.
- Info — an individual zip-entry-name path-traversal check for plugin uploads was not confirmed one way or the other (the archive-level size/count/ratio hardening is real and verified; per-entry name sanitization at extraction time lives outside the file reviewed).

**Verified safe, with direct evidence:** IDOR protection on assessments/reports (fails closed, 404 not 403, to avoid confirming existence); mass-assignment protection on self-registration (role is always server-assigned, `extra="forbid"` on the registration body); command injection (all scanner subprocess calls use `shell=False` with an argument list, never a formatted string, across every adapter checked).

---

## KingSec Self-Security Assessment

- **Scanner execution / command injection — VERIFIED SAFE.** Single chokepoint (`SubprocessCommandRunner`), `shell=False` always, argv lists, never string interpolation.
- **SSRF on scan targets — no technical restriction (by apparent design, unconfirmed as intentional).** `localhost`, `127.0.0.1`, `169.254.169.254` (cloud metadata), and RFC1918 ranges all pass target validation. This is plausible for a tool meant to scan internal infrastructure, but it means "authorization to scan X" is enforced only by a free-text, self-attested `authorized_by` field, not any technical control. Recommend explicit product-owner confirmation this is intended.
- **SSRF on outbound integration URLs (webhook/SIEM/ticketing) — VERIFIED SAFE.** A real validator blocks loopback/RFC1918/link-local/metadata ranges for every outbound call the app makes on a user's behalf.
- **File handling — VERIFIED SAFE.** No path built from user input for report downloads (in-memory generation, repository lookup by ID only). Plugin upload has real size/type/zip-bomb hardening at the archive level.
- **Docker — VERIFIED SAFE.** Non-root runtime user, no socket/host mounts, hardened compose (`read_only`, `no-new-privileges`, loopback-only host bind).
- **Secrets — VERIFIED, no functional hardcoded secrets found** anywhere in source, Dockerfile, or compose. Code defaults for required secrets are inert placeholder strings, not usable fallbacks. A genuinely strong structured-logging redaction processor exists and is applied globally (by key name, by `SecretStr` type, and by value-shape regex), failing closed.
- **The two confirmed authorization gaps above** (worker management, distributed queue) are the most significant self-security findings in this audit.

---

## Test Suite Assessment

Ran the full existing suite, unmodified, in this session:

- **Backend (`pytest`):** **2,718 tests collected and run, 2,718 passed, 0 failed, 0 skipped, 0 errors, 3 warnings, 144.78s.**
- **Frontend (`vitest`):** **60 test files, 273 tests, all passed, 68s.**
- **Linting:** `ruff check .` — clean on the tracked codebase (the only errors observed in this session were on untracked, auto-generated test-pollution files created *by running the suite itself* — see Current Defects). `mypy src` — 17 pre-existing errors across 8 files, none related to any area covered by this audit's fresh findings.

**What the tests actually prove vs. don't, per the audit's own explicit distinction:** 8 of 9 scanner adapters are tested exclusively against a `FakeRunner` test double — this proves "the adapter correctly builds arguments and parses a given mock output," it does **not** prove "the real binary, invoked for real, produces usable results on this system." Only Nuclei has a genuine subprocess-level integration test. The volume and breadth of the suite (2,718 tests, touching nearly every module) is real and substantial, but its *depth* on the specific question "does this actually work against a real external tool" is thin outside Nuclei. Playwright end-to-end tests exist in the frontend but are never executed in CI, so their current pass/fail status is genuinely unknown.

---

## Frontend Assessment

56 routed pages, all lazy-loaded, organized under real authentication/role guards (`AuthGuard`/`RoleGuard`) that are genuinely enforced (verified by reading the guard components, not assuming from route config) and re-verify the session against the backend on every protected-tree mount, not just trusting local state.

A representative sample of major pages (login, assessments list/detail, findings, reports, admin, license, settings) was checked directly against source: the overwhelming majority call real API functions, have real loading states (skeletons) and real error states (retry-capable, not blank-on-failure), not mock data. Assessment execution progress uses genuine adaptive-interval polling (3s while non-terminal, self-terminating on completion) with a real per-scanner status display and a real cancel action — not a fake spinner.

This repository already contains its own prior frontend audit (`docs/audits/dead-button-audit-2026-08.md`, `-filtered-2026-08.md`), inventorying ~345 interactive elements across 45 screens: **~89% (~308) genuinely working**, ~22-26 "Dead-A" (trivial wiring gap — backend endpoint exists, frontend just doesn't call it, e.g. the Assessments-list search/status/sort filters, confirmed still broken against current code), ~9-10 "Dead-B" (genuine unbuilt features — no Schedules CRUD UI despite a fully built backend lifecycle, no Plugins Marketplace install flow, Compliance's Gap Analysis/Report tabs are static copy over real unused endpoints).

**One specific cross-check confirmed the prior audit has already partially drifted from current code** (in the positive direction): the Playbook detail page's "no edit form" finding is **resolved** — a real edit form now exists, added in a commit that landed after the audit's snapshot. Treat the prior audit as a snapshot under active, ongoing iteration, not a frozen ground truth — but its remaining claims were spot-checked and found still accurate.

**Overall verdict: substantially and genuinely implemented**, consistent with a mature product mid-iteration, not a scaffold or facade.

---

## Documentation vs. Reality

| Documented Claim | Actual Implementation | Verdict |
|---|---|---|
| "9 pluggable scanners: Nmap, Nuclei, Nikto, FFUF, Gobuster, Trivy, Semgrep, Amass, OWASP ZAP" | All 9 have dedicated adapter + parser files, real and wired | **MATCHES** |
| README: "This container serves the REST API only — there is no built-in frontend hosting yet." | The Docker image (the actual shipped artifact) *does* bundle and serve the built frontend same-origin; the Dockerfile explicitly copies the frontend build into the backend's static directory before packaging | **CONTRADICTS** |
| "Multi-format reports: JSON, HTML, PDF, CSV, Markdown with executive scoring" | Only PDF and HTML exist in the live report adapter; no format-selection field even exists on the generate-report API body | **CONTRADICTS** |
| CHANGELOG: "multi-format report download via API with format negotiation" | No format negotiation exists in the current download endpoint | **CONTRADICTS** |
| "Bring-your-own-AI-key. Credentials stored encrypted at rest." | Confirmed real encryption call before persistence, not a misleadingly-named plaintext field | **MATCHES** |
| "Safe by default. Server binds to 127.0.0.1." | Confirmed loopback default with an explicit env-var guardrail required to bind wider | **MATCHES** |
| CHANGELOG 1.0.1: "Removed: 103 empty Alembic migration files (`*__no_changes.py`)" | The same low-signal naming pattern has recurred: 9 more exist today, spanning dates after that cleanup, including one generated *during this very audit's test run* | **PARTIALLY MATCHES** — the underlying problem (a test that pollutes the versions directory) was never actually fixed, only cleaned up once |
| "v2.0.0 — General Availability. Production-ready with full security hardening" | Not supported by the confirmed High-severity authorization gap, the confirmed error-visibility defect, and the two contradicted capability claims above | **UNVERIFIABLE AS STATED / not supported by evidence** |
| CI runs the frontend's e2e suite | `ci.yml`'s frontend job never invokes `playwright test` | **CONTRADICTS** (as an implicit claim of e2e coverage) |

---

## Current Defects

1. **[Confirmed, proven] Assessment failure reason is captured but never reaches the client.** `AssessmentView.from_domain()` omits `failure_reason`; the HTTP schema has no field for it. Every `FAILED` assessment shows a bare status with no explanation through the one endpoint clients actually use.
2. **[Confirmed, High severity] `worker_routes.py` has no authorization check on any route**, including delete. Any authenticated user can disrupt distributed scan infrastructure.
3. **[Confirmed, Medium severity] `distributed_routes.py`'s queue-mutation endpoints have no authorization check**, inconsistent with the parallel `queue_routes.py` implementation.
4. **[Confirmed] Malformed scanner output is silently indistinguishable from a clean scan.** Parse errors are logged and swallowed into an empty findings list.
5. **[Confirmed] A non-zero scanner exit code with partial findings is silently treated as full success** (at least for Nmap; the same pattern likely recurs in siblings, not exhaustively re-checked per adapter).
6. **[Confirmed] Zero finding deduplication anywhere in the codebase.**
7. **[Confirmed] Trivy and Semgrep cannot be driven with realistic input** — the domain model has no target type either tool's real CLI usage requires.
8. **[Confirmed] Recurring test-suite hygiene bug**: `test_autogenerate_on_clean_state_produces_no_changes` writes a real, untracked migration file into `src/kingsec/alembic/versions/` on every full test run (reproduced live during this audit — two such files were generated by this session's own test execution and were deliberately left in place, per this audit's "do not delete files" rule, as direct evidence of the defect).
9. **[Confirmed] Two disconnected, dead-code duplicate subsystems**: a fully dead second license-parsing implementation, and a superior-but-unused Finding/Report schema pair that actually has the scanner-attribution column the live schema lacks.
10. **[Confirmed] Low-severity: username/email enumeration on registration**, contradicting the code's own docstring.
11. **[Confirmed] Low-severity: unauthenticated `/healthz/ready` leaks raw exception text** on a backend failure.
12. **[Not independently reproduced, static-code finding] `/healthz/ready`'s exception-leak was confirmed by reading the code path, not by triggering a live database/filesystem failure** — flagged as CONFIRMED (static) rather than fully live-verified.

---

## Missing Capabilities

- A domain concept for container-image and local-source-path targets (blocking real Trivy/Semgrep usage).
- Finding deduplication of any kind.
- A structured, queryable scanner-attribution field on the live Finding schema.
- Real correlation logic behind the "Correlating" execution phase.
- Any connection between the real threat-intelligence/exploitability subsystem and actual scan findings.
- Any connection between real finding counts and asset criticality scoring (currently driven by manually-POSTed integers).
- CSV/JSON/Markdown/SARIF report export, despite being documented as existing.
- CI execution of the existing Playwright e2e suite.
- A staleness indicator on generated reports relative to the live assessment state.

---

## Industrial Readiness Scorecard

Scored independently, 0–5, against the evidence gathered above — not inflated for code sophistication, not deflated for cosmetic issues.

| # | Category | Score | Basis |
|---|---|---|---|
| 1 | Architecture | 3/5 | Dependency direction genuinely clean and grep-verified; real hexagonal boundaries. Offset by dead bytecode remnants, two dead-weight duplicate subsystems, and misleadingly-named "Legacy" classes that are actually live. |
| 2 | Functional correctness | 2/5 | Core lifecycle works, but zero-findings vs. silent-failure is indistinguishable, and non-zero-exit-with-partial-output is silently treated as success. |
| 3 | Scanner integration | 3/5 | All 9 real and wired; 2 of 9 (Trivy, Semgrep) cannot be driven with realistic input via the current domain model. |
| 4 | Detection reliability | 2/5 | Malformed output silently becomes "zero findings, no error" — a real false-negative risk with no visibility. |
| 5 | Finding accuracy | 2/5 | Severity/CVSS genuinely sourced, not fabricated (a real strength) — but zero dedup and no queryable scanner attribution. |
| 6 | Risk intelligence | 2/5 | Real components exist (CVSS, executive score, AI enrichment with correctly-preserved severity) but most of the claimed intelligence (correlation, exploitability, exposure, asset criticality) is disconnected from the actual findings pipeline. |
| 7 | Reporting | 4/5 | The strongest subsystem — internally consistent, honest, complete, well-tested. Docked for the false multi-format claim and the report-staleness gap. |
| 8 | API reliability | 3/5 | Broad, mostly-consistent structured error handling and verified IDOR/mass-assignment protections, offset by two confirmed real authorization gaps. |
| 9 | Security of KingSec itself | 3/5 | Command injection, file handling, Docker hardening, secret handling, and log redaction all verified sound — offset by the confirmed High-severity worker-management authorization bypass. |
| 10 | Test coverage | 3/5 | Large (2,718 + 273 tests, all passing) and broad, but explicitly mock-heavy for scanner integration — depth on "does this really work against a real tool" is thin outside Nuclei. |
| 11 | Integration testing | 2/5 | Only one scanner (Nuclei) has a genuine subprocess-level integration test. |
| 12 | End-to-end testing | 1/5 | Playwright e2e exists but is never run in CI; current pass/fail status is genuinely unknown. |
| 13 | Observability/logging | 3/5 | Real structured logging and a genuinely strong redaction layer; one confirmed silent-swallow path exists (in dead code, but real). |
| 14 | Error handling | 2/5 | The audit's central confirmed defect (FAILED-visibility) lives here, plus a dual raw/structured HTTPException idiom still coexisting. |
| 15 | Frontend completeness | 4/5 | ~89% of interactive elements genuinely working across 56 routes, real guards, real polling, honest loading/error states. |
| 16 | Documentation | 2/5 | Multiple confirmed, material contradictions between documented capability claims and actual code, including the "production-ready" framing itself. |
| 17 | Deployment/reproducibility | 3/5 | Docker build and export were independently proven portable this session (full clean-cache-wipe verification) — a real strength — but the required secrets have zero defaults and zero guidance in the shipped compose file, so it does not run out of the box. |
| 18 | CI/CD | 3/5 | A real, multi-version, multi-tool quality gate runs on every push — offset by the e2e-suite-never-invoked gap. |
| 19 | Performance | 0/5 | No performance/load testing evidence found anywhere in this audit — absence of evidence is not evidence of adequacy, scored as unassessed/inadequate rather than assumed fine. |
| 20 | Release readiness | 2/5 | The combination of a confirmed authorization bypass, a confirmed core-loop error-visibility defect, two non-functional scanners, and contradicted capability claims are release blockers for a security product being marketed as production-ready. |

---

## What KingSec Can Actually Do Today

**(A) What KingSec PROVES it can do**, demonstrated by code and runtime/test evidence:
- Create, authorize, and run a real security assessment against a hostname, IP address, URL, or CIDR network, using any of 7 scanners whose declared capability actually matches their real invocation.
- Persist real findings with genuinely scanner-sourced severity and (for Nuclei/Trivy) CVSS data.
- Render a complete, internally-consistent, honest PDF/HTML report, including scanner-coverage and limitations sections.
- Enforce real JWT/MFA authentication and role-based access control for the large majority of its API surface.
- Build, export, and reload a genuinely portable Docker image from a completely clean cache (independently re-verified this session).

**(B) What KingSec appears designed to do**, with the architecture/spec present but implementation or verification incomplete:
- Multi-scanner correlation and deduplication (a phase exists in the UI; no logic behind it).
- Full risk intelligence (exploitability, exposure, asset criticality, attack-path analysis) — real formulas and domain models exist but are disconnected from the actual findings pipeline.
- Trivy/Semgrep-based container-image and source-code scanning.
- Multi-format report export.

**(C) What KingSec cannot currently prove:**
- That any scanner other than Nuclei produces correct results against a real binary (only mock-tested).
- That IPv6 or CIDR-network targets actually work end-to-end (zero test coverage for either).
- That the frontend's Playwright e2e suite currently passes (never run in CI).

**(D) What is BROKEN:**
- Assessment failure visibility (proven).
- Worker-management and distributed-queue authorization (proven).
- Malformed-output-as-silent-success (proven).
- Trivy/Semgrep realistic-input usability (proven).

**(E) What is MISSING:**
- See "Missing Capabilities" above.

---

## Release Blockers

**P0 — Release blockers:**
- Worker-management authorization bypass (`worker_routes.py`) — any authenticated user can delete real distributed infrastructure.
- Assessment `FAILED` state provides zero diagnostic information to any real client — makes the core product loop appear randomly, unexplainably broken.
- Documented "production-ready, full security hardening" claim is not supported by the evidence in this audit and should not be shipped as-is to paying customers without remediation of the above.

**P1 — Critical before serious external testing:**
- Distributed-queue authorization gap (`distributed_routes.py`).
- Malformed scanner output silently presenting as a clean scan (false-negative risk in a security product).
- Non-zero scanner exit with partial output silently treated as full success.
- Trivy/Semgrep non-functional against realistic input — either fix the domain model or clearly disable/hide these two scanners until they are.

**P2 — Important product improvements:**
- Finding deduplication.
- Queryable scanner-attribution field on the live Finding schema.
- Wire the real risk-intelligence formulas (exploitability, asset criticality) to actual finding data instead of manually-supplied inputs.
- Correct the multi-format-report and frontend-hosting documentation claims to match reality.
- Run the existing Playwright e2e suite in CI.
- Fix the recurring alembic-test repo-pollution bug at its root (the test itself, not just periodic manual cleanup).

**P3 — Future improvements:**
- Real-binary integration tests for the 8 scanners currently verified only against `FakeRunner`.
- IPv6 and CIDR-network end-to-end test coverage.
- Report staleness indicator relative to live assessment state.
- Remove the two confirmed-dead duplicate subsystems (license parser, `scan_findings`/`scan_reports` schema) or actually adopt the better one.
- Performance/load testing of any kind — currently entirely unassessed.

---

## Recommended Next Phase

1. Fix the assessment `failure_reason` DTO gap and the two authorization gaps immediately — all three are small, well-localized, high-confidence fixes with the exact file:line already identified in this audit.
2. Decide explicitly (product-owner sign-off, not an engineering assumption) whether unrestricted scan-target SSRF exposure (localhost/RFC1918/metadata all currently scannable) is intended behavior for this product's threat model, and document that decision either way.
3. Either give Trivy/Semgrep a real target type they can use, or disable them from the active scanner registry until that work is done — shipping two scanners that cannot function as documented is worse than not listing them.
4. Correct the README/CHANGELOG claims this audit found contradicted by code before any external-facing use of that documentation.
5. Only after the above: proceed to controlled external testing with the 7 functioning scanners, with clear internal acknowledgment that findings are not deduplicated and reports can go stale relative to live assessment state.

---

## Evidence Appendix

Full agent-level research transcripts (scanner/target inventory, assessment lifecycle/failure trace, findings/risk/reporting pipeline, API/security enumeration, frontend page-by-page verification, architecture/documentation cross-check) were produced as part of this audit's methodology and are summarized in full above with file:line citations inline in each section. Representative file paths referenced throughout this audit:

- `src/kingsec/domain/{assessment.py, target.py, finding.py, report.py, enums.py, asset.py, attack_surface.py}`
- `src/kingsec/application/{use_cases/create_assessment.py, submit_assessment.py, use_cases/start_assessment.py, dto.py, service_api.py, threat_intelligence/risk_calculator.py}`
- `src/kingsec/infrastructure/scanner/{runner.py, orchestrator.py, provisioning.py, nmap.py, nuclei.py, nikto.py, ffuf.py, gobuster.py, amass.py, trivy.py, zap.py, semgrep.py}` and matching `*_parser.py` files
- `src/kingsec/infrastructure/persistence/{models.py, mappers.py, unit_of_work.py, _legacy_repositories.py, provisioning.py}`
- `src/kingsec/infrastructure/{licensing/parser.py, ai/adapter.py, ai/client.py, ai/providers.py, reporting/templates.py, reporting/renderer.py, reporting/adapter.py, notifications/url_validator.py, logging/redaction.py}`
- `src/kingsec/adapters/inbound/web/{routes.py, worker_routes.py, distributed_routes.py, queue_routes.py, schemas.py, versioning.py, spa.py, app.py}`
- `src/kingsec/bootstrap/composition.py`
- `frontend/src/{routes/index.tsx, components/shared/RouteGuards.tsx, api/client.ts, hooks/use-execution.ts, pages/AssessmentsPage.tsx, pages/AssessmentDetailPage.tsx, pages/LicensePage.tsx}`
- `docs/audits/dead-button-audit-2026-08.md`, `docs/audits/dead-button-audit-filtered-2026-08.md` (pre-existing, cross-checked, incorporated)
- `.github/workflows/{ci.yml, release.yml}`, `Dockerfile`, `docker-compose.yml`

Test execution logs (this session): backend `pytest -q` — 2,718 passed, 0 failed, 144.78s; frontend `vitest run` — 273 passed across 60 files, 68s; `ruff check .` — clean on tracked files; `mypy src` — 17 pre-existing errors, 8 files, unrelated to this audit's findings.
