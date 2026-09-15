# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog, and the project aims to follow Semantic Versioning.

## [Unreleased]
### Security
- **Breaking default change:** self-registration (`POST /auth/register`) is now **disabled by default**. Previously, the first user ever registered was automatically granted Admin — on any network-reachable instance, whoever reached `/auth/register` first permanently owned the system. Self-registration no longer grants Admin under any circumstances, even when re-enabled; the initial administrator is now created only by `kingsec-bootstrap`.
- **Upgrade impact:** if your deployment relied on open self-registration (e.g. letting analysts sign themselves up as Viewers), that endpoint now returns `403` immediately after upgrading. Set `KINGSEC_SECURITY__ALLOW_SELF_REGISTRATION=true` to restore the old signup availability — accounts created this way are always Viewer, never Admin, regardless of registration order. Deployments that already have an administrator (effectively every real deployment) see no other behavior change.
- Added `AuditAction.ADMIN_BOOTSTRAPPED`: admin creation via `kingsec-bootstrap` is now audit-logged (previously the one deliberate admin-creation path had no audit trail at all) and distinguishable from a self-registered `USER_REGISTERED` entry.
- `kingsec-bootstrap` now validates the supplied password against the same policy self-registration already enforced (previously unvalidated — the most privileged account in the system had a weaker bar than a Viewer).
- `GET /health` now reports `bootstrap_required: bool`, so an operator (or monitoring) can tell a fresh, never-bootstrapped instance apart from a normal one without reading source or provoking `/auth/register`'s new 403.
- Removed `AccountLockoutService` (`infrastructure/security/lockout.py`) — an in-memory, single-process progressive-lockout implementation that was fully built and tested but never wired into the live login path, which uses a separate, DB-backed mechanism with a fixed (non-escalating) lockout duration. See `docs/STATUS.md`'s Phase 3 section for the full account-lockout investigation.

## [2.0.0] - 2026-07-30
### Added
- General Availability release, consolidating 33 phases of development into a production-ready product (see RELEASE_NOTES.md for the full feature list: Attack Surface Management, multi-scanner Vulnerability Management, AI Copilot, Playbooks, Continuous Monitoring, Threat Intelligence, Compliance Dashboard, Asset Inventory, SSO/IdP configuration, Plugin SDK, Distributed Workers, Backup/Restore, License management)
- Installer scripts for Windows (`scripts/install.ps1`) and Linux/macOS (`scripts/install.sh`)

### Fixed (post-RC1 production-readiness audit)
- Cross-user access control gap allowing any authenticated user to read/modify other users' assessments, findings, and reports
- Repository-wrapper TypeError that would 500 every `GET /findings` and `GET /reports` request
- AI Copilot context builder silently returning no context due to a DI resolution mismatch
- Scanner Health/discovery endpoints blocking the entire asyncio event loop under concurrent load
- 30 of 32 "not found" application errors falling through to a generic 500 instead of 404
- Nmap hostname scans ~20x slower than IP scans due to a missing `-n` flag
- Pipeline pause/resume silently no-op'ing while claiming success; Queue pause/resume were unimplemented stubs; pipeline advancement existed but was never exposed through any route
- Missing pagination on Asset Inventory; undebounced search on three pages; missing confirmation dialogs on two destructive actions
- Compliance framework display names rendering as mangled auto-generated strings (e.g. "Mitre Att Ck") instead of proper names

### Documentation
- Rewrote INSTALL.md and QUICK_START.md to match actual shipped install/run behavior (no fictional CLI subcommands or PyPI package; documented the mandatory `KINGSEC_SECRETS__ENCRYPTION_KEY`, the frontend/backend split, and Windows PDF-generation prerequisites)
- Added CODE_OF_CONDUCT.md
- Replaced the stale v1.1.0 RELEASE_NOTES.md with accurate v2.0.0 content
- Corrected ROADMAP.md's version numbering and current-release marker

## [1.1.0] - 2026-07-27
### Added
- Report Center: professional-grade frontend for report management, preview, download, and regeneration
- Report search with debounced text, severity filter, and sort by date/score/target
- Report preview drawer with executive score ring, risk summary bars, finding distribution, and metadata
- Lazy-loading event log in ExecutionProgressPanel (only fetches when expanded)

### Fixed
- Missing auth token in useRegenerateReport causing 401 on regeneration (`frontend/src/hooks/use-reports.ts`)
- Unbounded `limit` parameter on 6 list endpoints — clamped to 1–200 (`routes.py`)
- `list_api_keys` returning `total=len(items)` instead of true database count (`list_api_keys.py`)
- Missing `limit`/`offset` fields in `ApiKeyListResponse` schema (`schemas.py`)
- SqlAlchemyUnitOfWork always rolling back on exit even after commit (`unit_of_work.py`)
- FindingsPage spinner flash on filter change — added `placeholderData` (`use-findings.ts`)
- Dashboard RecentReportsSection showing "No reports" on API error (`DashboardPage.tsx`)
- Duplicate query keys between findings and dashboard hooks causing cache fragmentation (`use-findings.ts`)
- Silent error swallowing in ReportsPage download/regenerate — added toast notifications (`ReportsPage.tsx`)
- Unstable useCallback dependency in ReportsPage (`ReportsPage.tsx`)

### Security
- Auth token injection in report regeneration API calls
- Input bounds enforcement on all paginated list endpoints

### Performance
- ExecutionProgressPanel event log only fetches when expanded, saving API calls
- Shared query keys for findings/dashboard endpoints eliminates duplicate cache entries

## [1.0.1] - 2026-07-23
### Added
- AssignRole use case with last-admin guard (`PUT /api/v1/users/{user_id}/role`)
- `kingsec-bootstrap` CLI for first-admin bootstrapping
- `AuditAction.ROLE_CHANGED` audit event
- MFA `/verify` and `/recovery` endpoints (unauthenticated)
- Session refresh endpoint (unauthenticated)
- Rate limiter periodic idle-eviction to prevent memory growth
- Format validation on `Target` hostname/IP/URL via `__post_init__`
- PluginInstaller wiring in composition (data_dir/plugins)
- OpenAPI allowlist test covering all 16 routers
- Dockerfile copies `README.md` and `LICENSE` in builder stage
- Locked requirements.txt with upper bounds on volatile deps
- `*_out.txt`, `*_err.txt`, `clean-env/` in .gitignore

### Changed
- Server binds to `127.0.0.1:8765` (removed insecure external bind)
- Auth error messages no longer leak token role value (structlog debug)
- `installer.py:40` path traversal guard uses `is_relative_to` instead of `startswith`
- All diagnostics endpoints gated with admin-only dependencies

### Removed
- Duplicate `PromoteUser` use case (subsumed by `AssignRole`)
- 103 empty Alembic migration files (`*__no_changes.py`)
- Scratch text files (`test_full_out.txt`, `test_queue_out.txt`, `tests_err.txt`, `tests_out.txt`)
- `clean-env/` development snapshot directory

### Fixed
- Missing `Role` import in `test_register_user.py` (ruff F821)

## [1.0.0] - 2026-07-20
### Added
- Module 1: project foundation - repository structure, dependency and tooling
  configuration, coding/naming/import/error/logging conventions, testing layout,
  Git branching strategy, CI architecture, and enforced hexagonal boundaries.
- Module 2.1: configuration system with hierarchical env-var loading (Pydantic Settings v2)
- Module 2.2: structured logging (structlog) with JSON and human-readable output modes
- Module 2.3: authentication system with JWT (access + refresh tokens), Argon2 password hashing,
  login/register/logout flows, token refresh, and Bearer auth middleware
- Module 2.4: RBAC authorization with role-based access control (ADMIN, ANALYST, VIEWER)
- Module 2.5: rate limiting with per-IP token bucket, separate auth/API limits
- Module 2.6: session management with refresh token rotation and session listing/revocation
- Module 2.7: MFA/TOTP support with enrollment, verification, and recovery codes
- Module 3.1: persistent job system with SQLAlchemy-backed job tracking, status management,
  retry support, and job lifecycle (schedule, run, cancel, archive)
- Module 3.2: event bus (in-memory) with publish/subscribe for decoupled domain events
- Module 3.3: thread-based job runner for background task execution
- Module 4.1: report generation with multiple output formats (JSON, HTML, PDF, CSV, Markdown)
- Module 4.2: multi-format report download via API with format negotiation
- Module 5: scanner orchestration framework with pluggable scanner architecture
- Module 5.1: Nuclei scanner integration for vulnerability scanning
- Module 5.2: AI enrichment pipeline (Bring-Your-Own-Key) for automated finding enrichment
- Module 5.3: Nmap scanner integration for network discovery
- Module 5.4: Nikto scanner integration for web server scanning
- Module 5.5: Trivy scanner integration for filesystem/container scanning
- Module 5.6: OWASP ZAP scanner integration for web application scanning
- Module 5.7: Semgrep scanner integration for static analysis
- Module 5.8: Amass scanner integration for subdomain enumeration
- Module 5.9: Gobuster scanner integration for directory enumeration
- Module 5.10: ffuf scanner integration for web fuzzing
- Module 6.1: Dashboard API with stats, recent scans, and trend data
- Module 6.2: Worker health API (status, uptime, queue depth)
- Module 6.3: Webhook notification system for scan completion events
- Module 6.4: Secrets management with encryption at rest (Fernet)
- Module 6.5: Backup/restore functionality for data portability
- Module 7: FastAPI-based REST API layer with OpenAPI documentation,
  CORS middleware, GZip compression, security headers, health endpoint,
  rate limiting middleware, and structured request logging
- Module 8: Production deployment - Dockerfile, docker-compose, Alembic migrations,
  schema validation at startup, production configuration defaults
- Hexagonal architecture enforcement (import-linter contracts)
- Pre-commit hooks for code quality (Ruff, mypy, gitleaks)
- Comprehensive test suite (403+ passing tests)

### Security
- Content Security Policy headers set to restrictive defaults
- Rate limiting enabled by default on auth and API endpoints
- Authorization gate enabled by default
- Server binds to loopback (127.0.0.1) by default
- Secrets stored as SecretStr (masked in logs/repr)
- Schema version validation on startup prevents un-migrated deployments
- JWT tokens with configurable expiration and refresh rotation
- Argon2 password hashing (memory-hard, resistant to GPU attacks)
- MFA/TOTP support for elevated security

### Fixed
- Authentication dependency injection (4 endpoint fixes in Phase 11.2)
- Argon2 password_hasher reference path (Phase 11.3)
- Base re-export path in infrastructure persistence (Phase 11.3)
- Dashboard COUNT query consolidation (26 queries to 6 GROUP BY in Phase 11.4)
- Session bulk UPDATE optimization (Phase 11.4)
- Queue repository EXISTS optimization (Phase 11.4)
- JSON serialization using json.dumps instead of str(__dict__) (Phase 11.4)

### Infrastructure
- GitHub Actions CI pipeline (lint, type, arch, security, test)
- Docker multi-stage build (slim, production-optimized)
- Docker Compose for orchestrated deployment
- uv-based dependency management (fast, reliable)
- Semantic versioning (1.0.0)
- Production release checklist and release automation
