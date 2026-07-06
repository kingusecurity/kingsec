# KingSec — Technical Design & Implementation Blueprint (v1)

| | |
|---|---|
| **Document** | Pre-implementation technical design (to be approved before any code) |
| **Product** | KingSec — local web application + reusable Python core |
| **Author** | Office of the CTO (Chief Software Architect & Lead Engineer) |
| **Status** | Awaiting founder approval — **no implementation code until approved** |
| **Frozen inputs** | Hexagonal architecture · local web app + reusable core · BYO AI key · orchestrate OSS scanners · job-based/milestone progress · authorization gate · the 7 approved screens |

> **How to read this.** Each section states the decision, then the *why* (and the trade-off rejected), in the spirit of one engineer explaining choices to another. Section 13 lists the handful of decisions I genuinely need your call on before we start. Everything here is *design* — interfaces and shapes, not working code.

---

## 1. Technology stack (and why each was chosen)

The guiding principle: **choose the simplest thing that satisfies the frozen constraints, and put anything that might change later behind a port** so the choice is reversible.

| Layer | Choice | Why this, and what we rejected |
|---|---|---|
| **Core language** | **Python 3.11+** | Frozen decision; richest security ecosystem; matches your learning goals. 3.11+ for real typing and speed. The core is pure Python with *no* framework or I/O imports. |
| **Local web server / API** | **FastAPI + Uvicorn** | The app runs on `localhost` and the browser talks to it. FastAPI gives async (essential for long scans without blocking), automatic request validation via Pydantic (a *security* control, not a nicety), and OpenAPI docs for free. *Rejected:* Django (too heavy for a single-user local app), Flask (weaker async + validation story). FastAPI is **one delivery adapter**, not the core. |
| **Async job execution** | **In-process `asyncio` job manager + DB-persisted state** | This is the most important "avoid unnecessary complexity" call. It's a **local, single-user** app, so a distributed queue (Celery/Redis/Temporal) would be over-engineering — extra services to install, run, and secure for no benefit. Scans run as async tasks in the app process; blocking scanner subprocesses run in a thread/process pool; job state is written to SQLite so a **browser refresh reconnects** (a frozen requirement). *Because it lives behind a `JobRunner` port, the future SaaS can swap in a real queue without touching the core.* |
| **Persistence** | **SQLite (via SQLAlchemy Core), behind a Repository port** | Embedded, zero-config, file-based, perfect for local single-user. Stores assessments, findings, report metadata, settings, job state. SQLAlchemy lives **only** in the persistence adapter (the core never imports it) and eases the future Postgres swap. *Rejected:* a server DB (needless for local); raw sqlite3 (SQLAlchemy pays off at the SaaS boundary). |
| **Scanner orchestration** | **Pure-Python checks where possible + Nuclei (subprocess) for templates** | Frozen: orchestrate OSS, don't build engines. Header, TLS, and DNS checks are done in **pure Python** (`httpx`, `sslyze`, `dnspython`) — fewer external binaries to bundle, easier to test, no redistribution headaches. Template-based vuln checks wrap **Nuclei** (MIT-licensed → safe to bundle). *See §13 for the Nmap licensing flag.* |
| **AI layer** | **Provider-agnostic `AIProviderPort`; adapters for OpenAI / Anthropic / local (Ollama)** | Frozen BYO-key model. The core passes *structured findings* to the port and gets back prioritization + plain-English guidance. Key never touches our servers. Swapping providers is an adapter, not a rewrite. |
| **Report generation** | **HTML/CSS template → PDF via WeasyPrint** | Our frozen report is already print-oriented HTML/CSS; WeasyPrint renders that to PDF, is far lighter to bundle than headless Chromium, and supports PDF metadata/tagging features we need for accessibility. *Rejected (for v1):* Playwright/Chromium — pixel-perfect but bundles a whole browser (heavy). Flagged in §13 as revisitable if fidelity/tagging fall short. |
| **Config** | **`pydantic-settings` + `platformdirs`** (non-secret) · **`keyring`** (secrets) | Validated config in a per-user app-data dir; the **API key in the OS secure store**, never in a file or log. Config is *injected into* the core (the core never reads env/files itself — the frozen hexagonal rule). |
| **Logging** | **`structlog` → rotating JSON file**, with redaction | Structured, correlation-ID'd, local-only, with a filter that guarantees secrets/PII never land in logs. |
| **Packaging** | **Briefcase or PyInstaller → native launcher per OS** | A non-technical SME shouldn't `pip install`. The app bundles the Python runtime + code + Nuclei into a double-clickable executable that starts the local server and opens the browser. *See §13.* |
| **Frontend delivery** | **The frozen HTML/CSS/JS screens served as static assets by FastAPI** | The screens we built are vanilla HTML/CSS/JS; serving them statically and having their JS call the local REST API keeps v1 free of build tooling. The API boundary still supports a React rewrite later if interactivity grows. |
| **Dev tooling** | **`ruff` + `black` + `mypy` + `pytest` + `pre-commit`** | Enforced formatting/lint/types/tests. CI runs SAST/SCA/secret-scan — we dogfood our own security posture (credibility for a security vendor). |

---

## 2. Architecture overview

Hexagonal (ports & adapters). **The one rule, restated: dependencies point inward.** The core defines interfaces (ports); everything else implements them and depends on the core, never the reverse.

```
        ┌──────────────────────────────────────────────────────────────┐
        │  DELIVERY (adapters)                                          │
        │  ▸ FastAPI local web server  ▸ static frontend (7 screens)    │
        │     (future: CLI · desktop · SaaS API — same core)           │
        └───────────────────────────┬──────────────────────────────────┘
                                     │ calls (plain data in / out)
                                     ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  APPLICATION / SERVICE  ← the Service API every wrapper calls │
        │  start_assessment · get_status · get_result · generate_report │
        │  orchestrates the domain + ports; returns DTOs only          │
        └───────────────────────────┬──────────────────────────────────┘
                                     ▼
        ┌──────────────────────────────────────────────────────────────┐
        │  DOMAIN  (pure Python, zero I/O — the crown jewels)          │
        │  Assessment · Finding · normalization/dedup · risk scoring ·  │
        │  assessment lifecycle (state machine)                        │
        └───────▲──────────────────────────────────┬───────────────────┘
                │ defines ports (interfaces)         │ implemented by
                └────────────────────────────────────┘
        ┌──────────────────────────────────────────────────────────────┐
        │  INFRASTRUCTURE (adapters — may do I/O)                       │
        │  Scanners (headers/TLS/DNS/Nuclei) · AI providers · SQLite ·  │
        │  Report renderer · Job runner · Config · Secrets · Logging   │
        └──────────────────────────────────────────────────────────────┘

        composition root wires concrete adapters into the core at startup
```

Why this shape: it's the frozen decision, and it's what makes "toolkit today, SaaS tomorrow" *additive* instead of a rewrite. It also directly delivers your "every module independently testable" principle — the domain tests with zero mocks, and each adapter tests in isolation against the port.

---

## 3. Project folder structure

```
kingsec/
├── core/                         # THE reusable engine — pure Python, no framework/I/O imports
│   ├── domain/
│   │   ├── models.py             # (spec) Assessment, Finding, value objects, enums
│   │   ├── normalization.py      # raw scanner output → unified Finding; dedup
│   │   ├── risk.py               # contextual risk scoring + effort estimation
│   │   └── lifecycle.py          # assessment state machine + phase definitions
│   ├── services/
│   │   ├── assessment_service.py # start/status/result/cancel — the Service API
│   │   ├── report_service.py     # generate_report use case
│   │   └── settings_service.py   # read/update settings
│   ├── ports/
│   │   ├── scanner.py            # ScannerPort (plugin interface)
│   │   ├── ai_provider.py        # AIProviderPort
│   │   ├── repository.py         # RepositoryPort
│   │   ├── report_renderer.py    # ReportRendererPort
│   │   ├── job_runner.py         # JobRunnerPort + ProgressEmitter
│   │   ├── config.py             # ConfigProvider
│   │   └── secrets.py            # SecretStore
│   └── dto/                      # plain-data shapes crossing the boundary
├── infrastructure/               # adapters implementing the ports (I/O allowed here)
│   ├── scanners/
│   │   ├── headers_scanner.py    # pure-Python
│   │   ├── tls_scanner.py        # sslyze
│   │   ├── dns_scanner.py        # dnspython
│   │   └── nuclei_scanner.py     # subprocess wrapper (JSON output)
│   ├── ai/                       # openai / anthropic / local adapters + prompt templates
│   ├── persistence/              # sqlite repository (SQLAlchemy) + migrations
│   ├── reporting/                # weasyprint renderer + report templates (frozen HTML/CSS)
│   ├── jobs/                     # asyncio job runner + DB-persisted job state
│   ├── config/                   # pydantic-settings + platformdirs loader
│   ├── secrets/                  # keyring adapter
│   └── logging/                  # structlog setup + redaction filter
├── api/                          # FastAPI delivery adapter
│   ├── main.py                   # app entrypoint (starts server, opens browser)
│   ├── routes/                   # REST endpoints → Service API
│   ├── schemas.py                # request/response Pydantic models (API DTOs)
│   └── static/                   # the 7 frozen screens (HTML/CSS/JS)
├── composition/
│   └── container.py              # composition root: build adapters, inject into services
├── tests/                        # unit / integration / e2e / security / fixtures
├── packaging/                    # Briefcase/PyInstaller specs + launcher
├── docs/                         # ADRs, this blueprint, runbooks
├── pyproject.toml                # deps + ruff/black/mypy/pytest config
└── README.md
```

**Dependency direction (enforced in review):** `api/` and `infrastructure/` may import `core/`; `core/` imports *nothing* from them. `composition/` is the only place that knows every concrete adapter. If `core/` ever imports `fastapi`, `sqlalchemy`, `httpx`, or an AI SDK, the boundary is broken.

---

## 4. How components communicate

**Two data flows.** The read path is simple request/response; the scan path is job-based because scans take minutes.

**Starting and watching an assessment (the job path):**
```
Browser (New Assessment screen)
  └─ POST /api/assessments {target, authorized}
       └─ api → AssessmentService.start_assessment(...)
            └─ validate + authorization guardrails (domain)
            └─ JobRunner.submit(assessment_id)     ── returns immediately ──►  {assessment_id}
                 (async) run phases: scanners → normalize → risk → AI
                 each phase completion → ProgressEmitter → persist to SQLite
Browser (Running Scan screen)
  └─ GET /api/assessments/{id}/status   (polls every ~1–2s)
       └─ reads persisted job state  ──►  {phase, completed_phases[], state, message?}
  └─ (refresh/reconnect) same GET rejoins the live job — never restarts
On completion:
Browser (Results screen)
  └─ GET /api/assessments/{id}          ──►  full AssessmentResult (DTO)
  └─ POST /api/assessments/{id}/report  ──►  ReportService → WeasyPrint → {report_path}
```

**Rules of the boundary:** the browser speaks HTTP/JSON to `api/`; `api/` translates to/from the **Service API**, which speaks **plain DTOs only** — never a FastAPI request object downward, never an ORM row or scanner object upward. Presentation lives entirely in the frontend; all logic lives in the core.

---

## 5. Service API contract (the boundary)

The operations every wrapper (this web app, and future CLI/desktop/SaaS) calls. **Job-based, plain data in/out.** Notation is a specification, not implementation.

```
# --- Assessments ---
start_assessment(target: str, authorized: bool, options: AssessmentOptions?) -> AssessmentRef
    # validates + runs authorization guardrails; enqueues async job; returns immediately
    # raises: InvalidTarget, NotAuthorized, TargetBlocked (guardrail)

get_assessment_status(assessment_id: str) -> AssessmentStatus
    # cheap, poll-friendly; drives the Running Scan screen and reconnect

get_assessment_result(assessment_id: str) -> AssessmentResult
    # only meaningful once state == COMPLETED (or COMPLETED_PARTIAL)

cancel_assessment(assessment_id: str) -> Ack
    # stops the job cleanly; guarantees no report is generated

list_assessments(limit: int?, offset: int?) -> list[AssessmentSummary]
    # powers Home + Reports

# --- Reports ---
generate_report(assessment_id: str, options: ReportOptions?) -> ReportRef
    # renders PDF from the SAME result object; returns saved path/id

# --- Settings & AI ---
get_settings() -> Settings
update_settings(patch: SettingsPatch) -> Settings
test_ai_connection(provider: AIProvider, key: SecretRef) -> ConnectionResult
    # lightweight local validation call; never echoes the key
```

Every input and output is a **DTO / primitive** (§6). `SecretRef` never carries the raw key across logs or responses — it's a handle resolved by the `SecretStore`.

---

## 6. Data models

Domain entities and the DTOs that cross the boundary. (Spec: `field: type — note`.)

**Enums**
```
AssessmentState : QUEUED | RUNNING | COMPLETED | COMPLETED_PARTIAL | CANCELED | FAILED
Phase           : DISCOVERY | ENCRYPTION_HEADERS | EXPOSURE | ANALYSIS | REPORT_READY
Severity        : CRITICAL | HIGH | MEDIUM | LOW | INFO
Effort          : MIN_15 | HOUR_1 | HALF_DAY | SEVERAL_DAYS       # time-based (frozen refinement)
AIProvider      : OPENAI | ANTHROPIC | LOCAL
```

**Domain entities**
```
Assessment
    id: str (uuid)              target: str            authorized: bool
    state: AssessmentState      current_phase: Phase?  completed_phases: list[Phase]
    created_at: datetime        completed_at: datetime?
    verdict: Verdict?           confidence: Confidence?
    findings: list[Finding]     error: str?            reference_id: str   # e.g. KS-2026-000014

Finding
    id: str                     title: str             # plain-language
    description: str            severity: Severity     effort: Effort?
    why_it_matters: str         how_to_fix: str?       # AI-generated, grounded
    evidence: dict              # sanitized technical detail (headers, TLS, banner…)
    source: str                 # which scanner produced it
    ai_generated_fields: list[str]   # transparency: which text came from the AI

Verdict
    status: Severity-derived label ("Needs attention" / "Looking good" / "Urgent")
    sentence: str               counts: {this_week:int, when_you_can:int, minor:int}

Confidence
    level: "High" | "Medium" | "Low"
    basis: str                  # e.g. "verified scanner evidence"

Report
    id: str   assessment_id: str   path: str   version: str   created_at: datetime
    branding: "kingsec" | "whitelabel"

Settings
    theme: "light"|"dark"|"system"   ai_provider: AIProvider
    business_name: str?              report_dir: str   include_appendix: bool
    telemetry_opt_in: bool           # off by default
    # NOTE: api_key is NOT here — it lives in the SecretStore only
```

**Boundary DTOs** (`AssessmentRef`, `AssessmentStatus`, `AssessmentResult`, `AssessmentSummary`, `ReportRef`, `ConnectionResult`) are flat, serializable projections of the above — no ORM objects, no domain methods, just data the UI renders.

---

## 7. Assessment lifecycle

A single explicit state machine (in `core/domain/lifecycle.py`), mapping 1:1 to the five milestones on the frozen Running Scan screen.

```
 created
   └─ authorize check ──(fail)──► rejected (NotAuthorized / TargetBlocked)
        └─(pass)─► QUEUED ─► RUNNING
                              ├─ DISCOVERY            (milestone 1)
                              ├─ ENCRYPTION_HEADERS   (milestone 2)
                              ├─ EXPOSURE             (milestone 3)
                              ├─ ANALYSIS  ← AI prioritization + guidance (milestone 4)
                              └─ REPORT_READY         (milestone 5)
                                   └─► COMPLETED
   any RUNNING state ──cancel──► CANCELED           (no report generated)
   unrecoverable error ─────────► FAILED
   partial (a scanner or AI step failed, rest succeeded) ─► COMPLETED_PARTIAL
```

**Progress & reconnect.** Each phase transition emits a progress event that is **persisted to SQLite** before the UI is told — so a refresh reads true current state and rejoins (frozen requirement). The `aria-live` milestone updates on the screen are driven by these *real* events, never a timer.

**Graceful degradation (frozen principle, made concrete):**
- A single scanner failing → log it, continue, mark that check "couldn't run," finish as `COMPLETED_PARTIAL`.
- The AI step failing → still produce results ranked by raw severity, flag "plain-English guidance unavailable," never fabricate. (Also honors "never paywall/hide a real finding.")
- A phase exceeding its soft time budget → the UI's "taking a little longer" copy; never a fake percentage.

---

## 8. Plugin architecture (scanners)

The mechanism that satisfies "orchestrate OSS, don't build engines" while keeping the core pure.

**`ScannerPort` (interface, spec):**
```
ScannerPort
    name: str                         # "headers", "tls", "dns", "nuclei"
    phase: Phase                      # which milestone it belongs to
    async run(target: str, ctx: ScanContext) -> list[RawFinding]
        # ctx carries timeouts, cancellation token, authorized scope
```

- Each scanner is an **independent adapter** implementing `ScannerPort`; it's testable in isolation by feeding a target/fixture and asserting the `RawFinding`s it returns.
- The engine **registers** the enabled scanners (composition root), runs those in a phase (concurrently where safe), and hands their `RawFinding`s to `normalization.py`, which maps them to the unified `Finding` model and deduplicates.
- **Two flavors, by design:** *pure-Python* scanners (headers via `httpx`, TLS via `sslyze`, DNS via `dnspython`) — no binaries to bundle, trivial to test; and *binary-wrapping* scanners (**Nuclei** via subprocess, parsing its JSON) for template-based checks. Preferring pure-Python where feasible minimizes bundling and licensing pain.
- **Adding a scanner later = one new adapter + one registration.** Nothing in the core changes. This is the "plugin" promise.
- **Safety inside the port:** every scanner receives the authorized scope and a cancellation token; none may reach outside the target; untrusted response content is treated as data, never executed.

---

## 9. Configuration system

- **Non-secret config** lives in a validated file (TOML/JSON) in the per-user app-data directory (`platformdirs`), loaded via `pydantic-settings`. Fields per `Settings` (§6): theme, provider, report prefs, telemetry opt-in.
- **Secrets (the API key)** live in the **OS secure store** via `keyring` — never in the config file, never in logs. The core receives config + a `SecretStore` handle **by injection** and never reads env/files itself (the frozen hexagonal rule; also what lets CLI/SaaS source config differently later).
- **Precedence:** built-in defaults → config file → runtime overrides. Everything validated on load; a corrupt config fails safe to defaults with a clear message.

---

## 10. Logging system

- **Structured JSON** via `structlog`, to a **rotating file** in app-data/logs — local only.
- **Correlation IDs** (assessment_id / request_id) threaded through every log line, so one scan is traceable end to end.
- **Redaction filter (mandatory):** API keys, and raw site/PII content, are never written — a security tool's logs must not become the leak. User-facing errors are sanitized (no stack traces to the UI); the full detail sits in the local log behind a correlation id the UI can surface.
- **Telemetry is separate and opt-in** (off by default), anonymized, and never carries sites or results — consistent with the Settings/Privacy design.

---

## 11. Update system

- **Signed manifest over HTTPS.** The app periodically (and on the Settings "Check for updates") fetches an update manifest, **verifies its signature against a bundled public key**, and only then trusts the advertised version/artifact.
- **Verify before apply:** download the artifact, check its hash/signature, prompt the user, then apply on restart. **Never auto-apply anything unverified** — non-negotiable for a security product (an unverified update path is a supply-chain backdoor).
- **Rollback-safe:** keep the prior version until the new one launches cleanly.
- Where a platform wrapper offers a vetted updater (e.g., desktop frameworks), we use it *with* signature verification rather than rolling our own crypto.

---

## 12. Testing strategy

The pyramid, plus security tests a security product can't skip. Every layer is independently testable *because* of the hexagonal boundaries.

- **Unit (most) — pure domain, zero mocks:** normalization/dedup, risk scoring, effort mapping, the lifecycle state machine, verdict derivation. Fast, deterministic.
- **Integration — adapters in isolation:** scanner parsers against **recorded fixture outputs** (a saved Nuclei JSON, a captured TLS result); the SQLite repository against a temp DB (incl. job-state persistence + reconnect); the AI adapter against a **mocked provider**; the report renderer against a fixture result.
- **Contract — the Service API:** each operation's inputs/outputs and error cases, so wrappers can rely on the boundary.
- **End-to-end (few):** the full flow via the API — start → poll → result → report — on a **deliberately vulnerable local target we own** (never a third-party site).
- **Security tests (first-class):**
  - *Prompt-injection:* fixtures where scanned content contains injection payloads ("ignore previous instructions…") must **not** alter AI behavior — assert the guardrails hold.
  - *Authorization guardrails:* internal/reserved ranges, loopback, and cloud-metadata IPs are **blocked** even with the box checked.
  - *Secret hygiene:* assert the API key never appears in any log or response.
  - *Report input escaping:* business name / paths can't inject into the PDF template.
- **AI evaluation harness:** prioritization/guidance quality and false-positive rate measured on curated fixtures, so "we improved the AI" is a number, not a vibe.
- **Golden-file tests** for report generation (stable HTML→PDF).
- **Tooling & CI gates:** `pytest` + coverage (target >80% on core logic), `ruff`/`black`/`mypy`, `pre-commit`, and CI running **SAST + SCA + secret-scanning** — we test ourselves the way we test customers.

---

## 13. Decisions I need from you before we start

A real CTO surfaces the forks rather than silently picking. These change implementation, so I'd like your call:

1. **Nmap in v1 — licensing flag (important).** Nmap's license restricts bundling/redistribution in a commercial product. My recommendation: **exclude Nmap from v1** and cover discovery/exposure with pure-Python checks + Nuclei (both cleanly licensed); revisit Nmap later as an *optional, user-installed* integration. Agree?
2. **PDF renderer:** confirm **WeasyPrint** for v1 (light, bundle-friendly, good enough for our print-styled report), with Playwright/Chromium held in reserve if fidelity/tagged-PDF accessibility fall short?
3. **Packaging target:** **Briefcase vs PyInstaller**, and which OS first (my instinct: get it solid on one — likely Windows *or* macOS depending on your student base — before the other)?
4. **Frontend approach:** confirm we ship the **frozen HTML/CSS/JS served statically by FastAPI** for v1 (no React build), keeping the API boundary open for a React rewrite later?
5. **Job model:** confirm the **in-process asyncio job manager + SQLite-persisted state** (rather than an external queue) as the right, non-over-engineered choice for a local app?
6. **AI providers at launch:** all three (OpenAI + Anthropic + Local/Ollama), or start with **one** and add the others as adapters? (One is faster to ship; the port makes adding the rest cheap.)

---

## 14. Proposed sequence (mapping to your phases)

Once the above is approved, I propose we implement in your stated order, one module at a time, each with tests before we move on:

1. **Phase 1 — Project structure:** the skeleton above + `pyproject.toml`, tooling, CI, composition root stub. *(Nothing runs yet, but the boundaries exist.)*
2. **Phase 2 — Backend architecture:** domain models, enums, ports, the Service API signatures, SQLite repository, config + secrets + logging wiring.
3. **Phase 3 — Assessment engine:** the lifecycle state machine, job runner, normalization/dedup, risk + effort — end-to-end with a *stub* scanner.
4. **Phase 4 — Scanner integrations:** headers → TLS → DNS (pure-Python) → Nuclei, each as a tested `ScannerPort` adapter.
5. **Phase 5 — AI summarization:** `AIProviderPort` + first adapter, grounded prioritization/guidance, prompt-injection defenses, graceful degradation.
6. **Phase 6 — Report generation:** WeasyPrint renderer against the frozen template, from the shared result object.
7. **Phase 7 — Frontend integration:** wire the 7 screens' JS to the local REST API (job polling, reconnect, downloads).
8. **Phase 8 — Packaging:** native launcher, bundling, update system.
9. **Phase 9 — Testing:** harden coverage, security tests, AI eval harness, golden files, E2E.

---

*End of blueprint. No implementation code has been written, per your instruction. On your approval — and your answers to §13 — I'll begin Phase 1, one module at a time, tests first, explaining each decision as we go.*
