# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog, and the project aims to follow Semantic Versioning.

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
