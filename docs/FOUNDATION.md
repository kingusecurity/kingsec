# KingSec — Module 1: Project Foundation

**Status:** Foundation delivered. This document is the engineering blueprint for the KingSec repository. It defines *structure, dependencies, and conventions only* — no application logic exists yet.

**Scope of this module:** everything a developer needs before the first line of business code — the folder structure and its rationale, the dependency set and its management strategy, the environment-configuration strategy, the coding/naming/import/error/logging conventions, the testing layout, the Git branching model, the CI architecture, and the project configuration files. What is deliberately *not* here is called out in §16.

**Frozen inputs (not redesigned here):** the hexagonal (ports-and-adapters) architecture with three ports (core↔UI, core↔AI-provider, core↔persistence); the Service API speaking only plain data types; bring-your-own-AI-key; milestone-based async jobs; and the trust guardrails (no paywalled critical findings, no fear-selling, no manufactured urgency, mandatory authorization gate before active scanning). This foundation *encodes* those decisions physically; it does not revisit them.

## Contents
1. Guiding principles
2. Repository layout
3. Folder-by-folder rationale
4. Dependencies
5. Environment configuration strategy
6. Coding standards
7. Naming conventions
8. Import conventions
9. Error-handling conventions
10. Logging conventions
11. Testing structure
12. Git branching strategy
13. CI/CD architecture (GitHub Actions)
14. Project configuration files
15. Decisions to freeze
16. Deliberately out of scope
17. Module 2 checklist

---

## 1. Guiding principles

The foundation exists to make the frozen architecture *cheap to follow and expensive to violate*. Five principles drive every choice below.

**Dependencies point inward.** In hexagonal architecture the pure core (`domain`, `application`) knows nothing about the outside world. The web framework, the AI provider, the database, and the PDF engine are all *details* that plug into ports the core owns. The folder layout mirrors this, and §8 shows how it is enforced automatically in CI — so an accidental `import fastapi` inside the domain fails the build rather than rotting the architecture silently.

**The boundary speaks plain data.** Nothing framework-shaped and no live domain object crosses the inbound port. Use cases accept and return DTOs (§7, §9). This is what lets the same core later serve a CLI, a desktop shell, or a SaaS API without change.

**Trust is encoded, not just documented.** The product's positioning — honesty as the conversion mechanism — shows up in the foundation itself: the server binds to loopback by default, the authorization gate defaults to *on*, logs redact secrets by design, and AI keys are user-supplied and git-ignored. These are defaults baked into config and conventions, not afterthoughts.

**Fast, boring feedback.** One formatter/linter (Ruff), strict typing (mypy), and a layered test pyramid run locally via `make check` and identically in CI. The tooling is deliberately conventional so effort goes into the product, not into arguing about style.

**Reproducible and portable.** Project metadata follows the PEP 621 / PEP 735 standards, so the dependency *manager* stays swappable; the environment is pinned by a lockfile; and the CI matrix tests the operating systems customers actually run — because KingSec ships to their machines, not ours.

---

## 2. Repository layout

```
kingsec/
├── .github/
│   └── workflows/                 # CI pipelines (YAML authored in Module 2)
├── docs/
│   ├── FOUNDATION.md              # this blueprint
│   └── adr/                       # Architecture Decision Records
├── scripts/                       # Dev/ops helper scripts (never shipped in the product)
├── src/
│   └── kingsec/                   # the installable package (src layout)
│       ├── domain/                # Layer 1 — pure business rules, zero external deps
│       │   ├── models/            #   entities & value objects
│       │   ├── events/            #   domain events
│       │   ├── errors/            #   domain exception types
│       │   └── services/          #   pure domain services
│       ├── application/           # Layer 2 — use cases + the core's port contracts
│       │   ├── ports/
│       │   │   ├── inbound/        #   driving port: the Service API (UI → core)
│       │   │   └── outbound/       #   driven ports: AI, persistence, jobs, reporting
│       │   ├── use_cases/          #   orchestration of the domain
│       │   ├── dto/                #   plain-data contracts that cross the boundary
│       │   └── errors/             #   application exception types
│       ├── adapters/              # Layer 3 — concrete implementations of ports
│       │   ├── inbound/
│       │   │   └── web/            #   local web app (FastAPI) — a driving adapter
│       │   └── outbound/
│       │       ├── ai/             #   AI provider adapter (bring-your-own-key)
│       │       ├── persistence/    #   local storage adapter
│       │       └── reporting/      #   PDF report generator adapter
│       ├── infrastructure/        # Layer 3 — technical concerns & composition
│       │   ├── config/            #   typed settings (pydantic-settings)
│       │   ├── logging/           #   structured logging setup
│       │   ├── jobs/              #   milestone-based async job runtime
│       │   └── bootstrap/         #   composition root (wires ports → adapters)
│       └── shared/               # shared kernel — primitives safe for any layer
├── tests/
│   ├── unit/                     # domain + application, no I/O
│   ├── integration/              # adapters against real local deps / mocked externals
│   ├── contract/                 # each adapter must satisfy its port's behaviour
│   ├── e2e/                      # drive the Service API end-to-end
│   └── fixtures/                 # shared test data
├── .editorconfig
├── .env.example
├── .gitignore
├── .pre-commit-config.yaml
├── .python-version
├── CHANGELOG.md
├── LICENSE                        # proprietary / commercial (placeholder)
├── Makefile
├── README.md
├── SECURITY.md
└── pyproject.toml
```

---

## 3. Folder-by-folder rationale

**`src/` layout (why not a flat package).** Putting the package under `src/` means the code you test is the *installed* code, not whatever happens to be in the working directory. It prevents a whole class of "works on my machine" import bugs, forces the packaging config to be correct, and keeps the import root unambiguous. It costs one extra directory and pays for itself the first time you package the app.

**The four layers.** The package splits into `domain`, `application`, `adapters`, and `infrastructure`, plus a `shared` kernel. This is the physical shape of the frozen hexagonal architecture:

- **`domain/`** is the centre: the entities, value objects, and pure services that model attack-surface and vulnerability concepts (assets, findings, severity, assessments, authorization). It imports nothing but the standard library and `shared`. `models/` holds the nouns; `services/` holds domain logic that doesn't belong to a single entity; `events/` holds the facts the domain announces; `errors/` holds the ways domain rules can be violated.
- **`application/`** is the use-case layer and the *owner of the ports*. `ports/inbound/` is the driving side — the Service API that a UI (or CLI, or SaaS handler) calls; the core defines this contract and the outside conforms to it. `ports/outbound/` is the driven side — the interfaces the core *needs*: an AI-provider port, a persistence port, a jobs/progress port, and a reporting port. The core defines these too, and adapters implement them. `use_cases/` orchestrates the domain to satisfy a goal; `dto/` holds the plain-data request/result objects that cross the inbound boundary; `errors/` holds orchestration-level failures.
- **`adapters/`** is where the outside world plugs in. `inbound/web/` is the local FastAPI app — a *driving* adapter that translates HTTP into Service-API calls. `outbound/ai/`, `outbound/persistence/`, and `outbound/reporting/` are *driven* adapters implementing the corresponding outbound ports. Swapping SQLite for Postgres later, or one AI provider for another, is a change confined to a single folder here.
- **`infrastructure/`** holds cross-cutting technical machinery that isn't a business port: `config/` (typed settings), `logging/` (structured logging setup), `jobs/` (the async runtime that executes milestone-based work), and `bootstrap/` (the composition root — the one place that knows which concrete adapter satisfies which port and wires them together at startup). Keeping wiring in a single composition root is what lets every other module depend on *interfaces* instead of on each other.
- **`shared/`** is a small shared kernel: primitives, type aliases, and constants that genuinely belong to no single layer and are safe for all of them to import. It is kept deliberately tiny — a dumping ground here becomes a hidden coupling later.

**`tests/` mirrors the architecture, not the file tree.** Tests are organised by *kind* (unit, integration, contract, e2e) because that's how you decide what to run when: the fast unit tier on every save, the slower tiers before merge. The `contract/` tier is specific to ports-and-adapters — it verifies that every outbound adapter actually behaves the way its port promises, which is what makes swapping adapters safe. §11 details this.

**Top-level support directories.** `.github/workflows/` will hold CI (its architecture is in §13; the YAML lands in Module 2). `docs/` holds this blueprint and the `adr/` decision log — ADRs are how the frozen decisions get a permanent, referenceable *why*. `scripts/` holds developer/operator helpers that are never part of the shipped product.

---

## 4. Dependencies

Two groups: the runtime stack the architecture requires, and the development toolchain. Foundation code exercises only the toolchain — the runtime packages are declared now so the stack is explicit and reviewable, and the code that uses them arrives in later modules.

### 4.1 Runtime stack

| Package | Role | Why this one |
|---|---|---|
| **fastapi** | Inbound web adapter | Async-native, typed, minimal; a clean fit for a local web app and for the "boundary speaks typed data" principle. Confined to `adapters/inbound/web`. |
| **uvicorn[standard]** | ASGI server | Runs the FastAPI app locally; `[standard]` pulls in the performant event-loop and HTTP tooling. |
| **pydantic** (v2) | Boundary DTOs + validation | Validates untrusted input at the edge and expresses the plain-data contracts. Used **only at the edges** (DTOs, settings) — never inside the domain, so the core stays framework-free. |
| **pydantic-settings** | Configuration | Loads the `.env` schema (§5) into a typed settings object with defaults and validation, instead of scattering `os.getenv` calls. |
| **httpx** | Async HTTP client | Talks to the user's AI provider and performs HTTP-level probing. Async matches the milestone-based job model. Confined to outbound adapters. |
| **structlog** | Structured logging | Produces structured, JSON-capable logs and supports processors — which is how secret redaction (§10) is enforced centrally rather than hoped for at each call site. |

Deliberately deferred (added in the module that first needs them, to keep the surface small): a PDF engine for the reporting adapter, any provider-specific AI SDKs (the adapter is provider-agnostic over `httpx` by default), and any heavier persistence layer (the local store starts on the standard-library `sqlite3`, behind the persistence port, so no dependency is needed yet).

### 4.2 Development toolchain

| Package | Role | Why this one |
|---|---|---|
| **ruff** | Lint **and** format | Replaces Black + isort + flake8 + several plugins with one fast tool. Fewer tools, one config, no formatter/linter disagreements. Its `S` rules also give inline security linting (flake8-bandit). |
| **mypy** | Static typing | Strict typing catches whole categories of bugs before runtime and makes the port/DTO contracts machine-checked. Runs with `strict = true`. |
| **pytest** | Test runner | The de-facto standard; concise tests, powerful fixtures, rich plugin ecosystem. |
| **pytest-cov** | Coverage | Measures and gates coverage; branch coverage on. |
| **pytest-asyncio** | Async tests | Needed to test async use cases and adapters. |
| **import-linter** | Architecture enforcement | The keystone: turns the hexagonal rules into CI-checked contracts (§8). Wrong-direction imports fail the build. |
| **bandit** | Deeper Python SAST | Defense-in-depth beyond Ruff's `S` rules — a security product should dogfood scanning. |
| **pip-audit** | Dependency CVE scanning | Flags known-vulnerable dependencies — table stakes for a security vendor. |
| **pre-commit** | Local enforcement | Runs the above on every commit so problems are caught at the keyboard, not in CI. |

Build backend: **hatchling** (simple, standards-based, understands the `src/` layout). Secret scanning in commits/CI is handled by **gitleaks** via its pre-commit hook (a binary, not a Python dependency), reinforcing the "no secrets in the repo" rule.

### 4.3 Dependency management strategy

- **Recommended manager: `uv`.** It resolves and installs an order of magnitude faster than the alternatives, and manages the virtual environment, the lockfile, and the Python version in one tool. *This is the one dependency-tooling decision to freeze (§15).*
- **Standards-based metadata.** Everything lives in `pyproject.toml` using PEP 621 (`[project]`) for runtime deps and PEP 735 (`[dependency-groups]`) for the dev-only group. Because the metadata is standard rather than tool-specific, switching managers later (uv ↔ PDM ↔ Poetry) is cheap — no lock-in.
- **Loose floors in `pyproject`, exact pins in the lockfile.** `pyproject` declares compatible *minimums* (`>=`); the committed lockfile pins exact, hashed versions so every machine and every CI run installs byte-identical dependencies. The lockfile is committed; the virtual environment is not.
- **Grouping.** Runtime vs. dev is a hard split so the shipped footprint never includes test/lint tooling.
- **Updates & security.** Dependency bumps are deliberate PRs (not silent), driven by `pip-audit` findings and periodic review; pre-commit pins are refreshed with `pre-commit autoupdate`. A vulnerable transitive dependency is a build failure to fix, not a warning to ignore.

---

## 5. Environment configuration strategy

Configuration follows twelve-factor discipline: **config lives in the environment; secrets never live in the repository.**

- **`.env.example` is the committed, documented template** listing every variable and its intent with *no values*. Developers copy it to `.env` (git-ignored) and fill in their machine's values. The example file is the single place to discover what's configurable.
- **`.env` is git-ignored**; `.gitignore` explicitly re-includes `.env.example` so the template stays tracked while real values never can be.
- **One typed settings object.** `infrastructure/config` will load these variables via `pydantic-settings` into a validated settings model with sane defaults — no scattered `os.getenv` reads, and invalid configuration fails fast at startup with a clear message.
- **`KINGSEC_` prefix** namespaces every variable so it's unambiguous in a shared shell and trivially filterable.
- **Trust defaults are encoded here.** `KINGSEC_HOST` defaults to `127.0.0.1` (local-first, not exposed); `KINGSEC_AI_API_KEY` is user-supplied, blank in the template, and used only on the local machine.

Variable groups: application (env, log level/format), local web server (host, port), persistence (data dir, db path), AI provider (provider, key, model, base URL, timeout), jobs (workers, timeout), and reporting (output dir). See `.env.example` for the annotated list.

---

## 6. Coding standards

- **PEP 8 as the baseline, Ruff as the enforcer.** Style is not a matter of opinion in review; the formatter settles it. Line length 100.
- **Type hints are mandatory.** Every function signature is typed; `mypy --strict` is a required gate. Untyped public code does not merge.
- **Docstrings on public modules, classes, and functions**, Google style (enforced by Ruff's `D` rules). The docstring says *why* and *what*; the code says *how*.
- **Pathlib over `os.path`, f-strings over `%`/`.format`, comprehensions over manual loops** where they read clearly — all nudged by Ruff.
- **No `print` for diagnostics** — use the logger (§10). No bare `except:` — catch specific exceptions (§9). No mutable default arguments. No wildcard imports.
- **Small, single-purpose functions and modules.** If a module needs a table of contents, it's two modules.
- **Security linting is part of "clean."** Ruff `S` rules run on every file; `bandit` runs in CI. A security product treats its own SAST findings as blocking.

At the foundation stage the standard is simply: production quality on the first commit that contains logic.

---

## 7. Naming conventions

| Thing | Convention | Example |
|---|---|---|
| Packages / modules | lower_snake_case | `use_cases`, `ai_provider` |
| Classes | PascalCase | `Assessment`, `FindingSeverity` |
| Functions / variables | lower_snake_case | `run_assessment`, `target_host` |
| Constants | UPPER_SNAKE_CASE | `DEFAULT_TIMEOUT_SECONDS` |
| Private members | single leading underscore | `_normalize` |
| Inbound (driving) port | `…ServiceApi` / `…Api` | `AssessmentServiceApi` |
| Outbound (driven) port | `…Port` | `AiProviderPort`, `PersistencePort` |
| Adapter (implements a port) | `…Adapter` | `HttpxAiAdapter`, `SqliteAdapter` |
| Use case | verb phrase | `RunAssessment`, `GenerateReport` |
| DTOs | `…Request` / `…Result` | `RunAssessmentRequest`, `AssessmentResult` |
| Domain error | `…Error` | `AuthorizationRequiredError` |
| Test files / functions | `test_…` | `test_rejects_unauthorized_scan` |

The `Port` / `Adapter` suffixes make the architecture legible at a glance: `…Port` is a contract the core owns; `…Adapter` is a replaceable detail.

---

## 8. Import conventions

- **Absolute imports within the package** (`from kingsec.domain.models import …`); relative imports only for tight sibling references, if at all. Ruff's isort orders imports into stdlib / third-party / first-party groups automatically.
- **The dependency-direction rule (the important one).** Imports may only point inward:
  - `domain` imports only the standard library and `shared`.
  - `application` imports `domain` and `shared` (and may use Pydantic for DTOs) — never adapters, infrastructure, or web frameworks.
  - `adapters` and `infrastructure` may import `application` and `domain`.
  - Only `infrastructure/bootstrap` (the composition root) is allowed to know about concrete adapters in order to wire them.
- **This is enforced, not trusted.** `import-linter` contracts in `pyproject.toml` encode the layering and the forbidden imports; `make arch` and CI run them. An `import fastapi` in the domain, or an `import kingsec.adapters` in the application layer, fails the build. This is what keeps the frozen architecture from eroding one convenient shortcut at a time.
- **Pydantic is an edge tool.** Permitted in `application` DTOs and in `infrastructure/config`; forbidden in `domain`, so the core carries no framework dependency.

---

## 9. Error-handling conventions

**A single exception root, with layered subtypes.** Every KingSec exception descends from one base so callers can catch broadly at the top of the process and narrowly where it matters. The taxonomy below is the *convention to implement in Module 2* — shown here as a shape, not as code:

```
KingSecError                     (base — never raised directly)
├── DomainError                  (a business rule / invariant was violated)
│   ├── AuthorizationRequiredError
│   └── InvalidTargetError            …etc. (added with the domain)
├── ApplicationError             (a use case could not complete)
│   └── UseCaseError                  …etc.
└── AdapterError                 (an external dependency failed)
    ├── AiProviderError
    ├── PersistenceError
    └── ReportingError
```

- **Adapters translate at the boundary.** An adapter never lets a raw `httpx` or `sqlite3` exception escape; it catches and re-raises as the matching `AdapterError` subtype (preserving the cause with `raise … from err`). The core therefore only ever handles *its own* exception vocabulary — a port's promise includes which errors it may raise.
- **The inbound boundary maps errors to plain data.** The Service API converts exceptions into typed, plain-data error results (a stable error code + a safe message). Stack traces and internal detail are logged, never returned to the UI.
- **Fail closed on safety.** The authorization gate raises `AuthorizationRequiredError` and blocks; there is no "assume authorized" path. Safety-relevant failures deny by default.
- **No silent failures.** No bare `except`, no swallowing exceptions, no `except: pass`. Either handle meaningfully or let it propagate. Expected, recoverable conditions are modelled as return values; truly exceptional conditions are exceptions.

---

## 10. Logging conventions

- **Structured logging via `structlog`**, one logger per module. Log *events with fields*, not interpolated prose, so logs are queryable.
- **Levels with intent.** DEBUG = developer detail; INFO = normal milestones (assessment started, report generated); WARNING = recovered/degraded; ERROR = a use case failed. Configurable via `KINGSEC_LOG_LEVEL`.
- **Console in dev, JSON in prod**, switched by `KINGSEC_LOG_FORMAT` — human-readable while building, machine-parseable in the field.
- **Secret redaction is central, not per-call.** A structlog processor redacts sensitive keys (API keys, tokens, target credentials) so a stray field can't leak a secret into a log line. **AI keys, tokens, and scan credentials are never logged.**
- **Correlation.** Long-running work carries a job/correlation ID on every line so a milestone-based assessment can be followed end-to-end.
- **An honest audit trail** for security-relevant events — authorization granted, scan started/stopped — recording real events only, never fabricated activity. No `print` statements anywhere.

---

## 11. Testing structure

Tests are organised by *kind*, mirroring the architecture rather than the file tree:

- **`unit/`** — the pure core (`domain`, `application`) with no I/O. Fast; runs on every save. Most tests live here, including the business rules (the authorization gate among them).
- **`integration/`** — a single adapter against a real local dependency (e.g. a temp SQLite file) or a mocked external service (e.g. a stubbed AI provider). Verifies the adapter works against the thing it wraps.
- **`contract/`** — the ports-and-adapters keystone: a shared suite of behavioural expectations that *every* implementation of a given outbound port must pass. This is what makes swapping adapters safe — a new persistence or AI adapter is "done" when it passes the port's contract tests.
- **`e2e/`** — drives the inbound Service API through a complete use case, exercising the wired-together system.
- **`fixtures/`** — shared test data and builders.

Conventions: `pytest` with markers (`unit`, `integration`, `contract`, `e2e`, `slow`) so tiers run independently; Arrange-Act-Assert structure; descriptive names that read as specifications (`test_rejects_unauthorized_scan`); branch coverage measured with a floor that rises as the codebase matures. Fixtures live in `conftest.py` files near where they're used. Test code is exempt from docstring rules and may use `assert` freely (configured in Ruff's per-file ignores).

---

## 12. Git branching strategy

For a solo founder heading toward a small team, heavy GitFlow is overhead without benefit. KingSec uses **trunk-based development (GitHub Flow):**

- **`main` is always releasable** and protected: no direct pushes; changes land through pull requests with all CI gates green.
- **Short-lived branches** named by intent: `feat/…`, `fix/…`, `chore/…`, `docs/…`, `refactor/…`. They live hours-to-days, not weeks, to avoid painful merges.
- **Conventional Commits** (`feat:`, `fix:`, `chore:` …) so history is readable and changelog/version automation becomes possible later.
- **Squash-merge** to keep `main` history linear and each change atomic.
- **Tags mark releases** (`v0.1.0`, …) following Semantic Versioning; a dedicated `release/` branch is introduced only if/when parallel release maintenance actually requires it — not before.

Fast iteration now; a clean, auditable history that scales when the team grows.

---

## 13. CI/CD architecture (GitHub Actions)

Architecture only — the workflow YAML is authored in Module 2. The pipeline encodes exactly what `make check` runs locally, so "green locally" means "green in CI."

**Triggers:** every pull request to `main`, push to `main`, and version tags (for the deferred release job).

**Pipeline (stages gate the merge; branch protection requires them to pass):**

```
      ┌─────────────┐
      │   Setup     │  checkout · install uv · restore cache · sync deps
      └──────┬──────┘
             │  (parallel quality gates)
   ┌─────────┼───────────┬───────────────┬───────────────┐
   ▼         ▼           ▼               ▼               ▼
┌───────┐┌────────┐┌──────────────┐┌──────────────┐┌───────────┐
│ Lint+ ││  Type  ││ Architecture ││   Security   ││   Tests   │
│ Format││ (mypy) ││(import-linter)││(bandit·audit·││ (matrix)  │
│(ruff) ││        ││              ││  gitleaks)   ││ +coverage │
└───┬───┘└───┬────┘└──────┬───────┘└──────┬───────┘└─────┬─────┘
    └────────┴────────────┴───────────────┴──────────────┘
                             │  all green
                             ▼
                       ┌───────────┐
                       │   Build   │  build sdist+wheel (packaging must work)
                       └─────┬─────┘
                             │  (on tag only)
                             ▼
                       ┌───────────┐
                       │  Release  │  deferred to a later module
                       └───────────┘
```

**Notes that matter:**
- **OS matrix.** Because KingSec runs on *customer* machines, tests run on Ubuntu, Windows, and macOS across supported Python versions (3.11–3.13). Cross-platform breakage is caught before customers hit it.
- **Fail-fast, cached.** Dependency and tool caches keyed on the lockfile keep runs quick; the quality gates run in parallel and any failure blocks the merge.
- **Security is a first-class stage**, not a nice-to-have: dependency audit (`pip-audit`), SAST (`bandit` + Ruff `S`), and secret scanning (`gitleaks`) all gate merges.
- **Build is a gate too** — proving the package builds every time prevents "it imports but won't ship" surprises.

---

## 14. Project configuration files

| File | Purpose |
|---|---|
| **pyproject.toml** | Single source of truth: project metadata (PEP 621), runtime deps, dev group (PEP 735), and all tool config — Ruff, mypy, pytest, coverage, and the import-linter architecture contracts. |
| **.env.example** | Documented, value-free template of every environment variable (§5). Copied to `.env` locally. |
| **.gitignore** | Excludes the virtual environment, caches, build artifacts, local data/reports, IDE files, and — critically — `.env`, while re-including `.env.example`. |
| **.python-version** | Pins the interpreter for `uv`/`pyenv` so everyone develops on the same Python. |
| **.pre-commit-config.yaml** | Hooks that run on commit: Ruff (lint+format), mypy, gitleaks (secret scan), and hygiene checks (large files, private keys, trailing whitespace, valid TOML/YAML). |
| **.editorconfig** | Consistent whitespace/encoding across every editor, independent of personal settings. |
| **Makefile** | Thin task shortcuts (`install`, `lint`, `type`, `arch`, `sec`, `test`, `check`, `clean`) so the same commands work locally and in CI. |
| **README.md** | Foundation-level orientation and developer quick-start; points here for detail. |
| **SECURITY.md** | Responsible-disclosure policy — expected of a security vendor. |
| **CHANGELOG.md** | Keep-a-Changelog history for release notes. |
| **LICENSE** | Proprietary/commercial notice (placeholder — replace with the real EULA, reviewed by counsel, before release). |
| **docs/FOUNDATION.md** | This blueprint. |
| **docs/adr/** | Architecture Decision Records — the permanent *why* behind frozen decisions. |
| **(lockfile)** | Generated by the chosen manager (e.g. `uv.lock`); pins exact, hashed dependency versions. Committed. |

---

## 15. Decisions to freeze

These are the genuine choices baked into the scaffold. Confirm or override before Module 2:

1. **Dependency manager: `uv`** (recommended). If you prefer PDM or Poetry, say so — the standards-based `pyproject` makes the switch cheap, but the Makefile and CI commands assume the choice.
2. **Python floor: 3.11**, dev on 3.12, CI matrix 3.11–3.13. Raising the floor to 3.12 buys nicer typing/perf at the cost of dropping 3.11 users.
3. **Line length 100** and **Google-style docstrings.** Both are one-line changes if you'd rather have 88 / NumPy style.
4. **Local persistence starts on standard-library SQLite** behind the persistence port (no dependency yet). Confirm before the persistence module.
5. **AI adapter is provider-agnostic over `httpx`** by default, with provider SDKs added as optional extras only if a provider needs them.
6. **Security toolchain:** secret scanning via **gitleaks**, SAST via **Ruff `S` + bandit**, dependency audit via **pip-audit**. Confirm this is what you want dogfooded.

## 16. Deliberately out of scope

To keep Module 1 to its mandate, the following were intentionally *not* produced: any domain models, use cases, ports, or DTOs as code; any FastAPI routes; any database schema or persistence code; the async job runtime's implementation; the AI or reporting adapters; and the CI workflow YAML (its architecture is in §13; the YAML is Module 2). The Python packages contain only one-line docstrings describing each package's responsibility — placeholders that make the structure real without pre-committing implementation.

## 17. Module 2 checklist

Proposed next module — "make it runnable and enforced," still no business logic. Confirm or resequence:

- [ ] Author the **GitHub Actions workflow YAML** from the CI architecture in §13 (setup → lint · type · arch · security · tests(matrix) → build), with the OS/Python matrix and caching.
- [ ] Implement **typed configuration** (`infrastructure/config`) loading the `.env` schema from §5 via `pydantic-settings`, with defaults, validation, and fail-fast on bad config.
- [ ] Implement **structured logging setup** (`infrastructure/logging`) per §10, including the secret-redaction processor and the console/JSON switch.
- [ ] Implement the **base exception hierarchy** from §9 (`KingSecError` → `DomainError` / `ApplicationError` / `AdapterError`) — taxonomy only, no rules yet.
- [ ] Stand up the **composition-root skeleton** (`infrastructure/bootstrap`) — the wiring seam where ports meet adapters, empty for now.
- [ ] Establish the **test harness**: `conftest.py`, the shared `fixtures/` dir, and one trivial passing test per tier to prove the pyramid is wired.
- [ ] Get a **green `make check`** on the still-empty package — proving the entire toolchain (lint, types, architecture contracts, security, tests, build) works end-to-end.
- [ ] Land **ADR-0001 (Hexagonal architecture)** and the other frozen-decision ADRs in `docs/adr/`.

*Domain modelling, the ports, and the first use cases begin in Module 3, once the spine above is green.*
