# KingSec v2.0.0 — GA Release Checklist

## Pre-Release Verification

### Code Quality
- [x] Ruff linting: 0 errors across 613 Python files
- [x] Ruff formatting: all files formatted
- [x] Unused imports (F401): 0 remaining
- [x] Unused variables (F841): 0 remaining
- [x] Boolean anti-patterns (E712): 0 remaining
- [x] Deprecated typing imports (UP035): cleaned up

### Testing
- [x] Unit tests: 3,253 passed, 0 failed
- [x] New Phase 32 tests: 76 passed
- [x] Pre-existing integration test failures documented (Alembic duplicate index)

### Frontend
- [x] TypeScript compilation: 0 errors in new pages
- [x] All 52 pages compile correctly
- [x] New pages (Deployment, License, Diagnostics, Release Audit) functional
- [x] Sidebar navigation updated

### Packaging
- [x] pyproject.toml: version updated to 2.0.0
- [x] Hatch build include paths corrected (alembic.ini, script.py.mako, versions)
- [x] __init__.py version updated to 2.0.0
- [x] Docker image tag updated to 2.0.0
- [x] README.md version updated to 2.0.0

### Docker
- [x] Dockerfile: all 15 runtime dependencies listed explicitly
- [x] Dockerfile: multi-stage build with non-root user
- [x] Dockerfile: health check configured
- [x] docker-compose.yml: security options (no-new-privileges, read-only)
- [x] docker-compose.yml: named volume for data persistence
- [x] .dockerignore: created (excludes .git, __pycache__, .env, node_modules)

### Security
- [x] JWT authentication with Argon2id password hashing
- [x] RBAC authorization (viewer/analyst/admin)
- [x] SSRF protection on all outbound HTTP clients
- [x] Plugin sandboxing (filesystem, timeout, memory limits)
- [x] Input validation (Pydantic + custom validators)
- [x] Security headers (HSTS, CSP, X-Frame-Options, Permissions-Policy)
- [x] Rate limiting (per-IP + per-user)
- [x] Account lockout with progressive delays
- [x] Path traversal protection on file operations
- [x] License validation with HMAC-SHA256 signatures

### Documentation
- [x] README.md updated for v2.0.0 GA
- [x] Version references consistent across all files
- [x] Release manifest generated
- [x] Release notes generated

## Known Issues (Pre-existing)
- [ ] Alembic migration `aabbccddee00` has duplicate index `ix_asset_tags_asset_id` — does not affect fresh installs
- [ ] Architecture violation in `application/playbooks/actions.py` importing from `infrastructure` — documented tech debt
- [ ] `bootstrap/production.py` is deprecated but still present — kept for backward compatibility
- [ ] Legacy audit bridge code in `verify_mfa_code.py` and `use_recovery_code.py`

## Post-Release
- [ ] Tag git commit as `v2.0.0`
- [ ] Build Docker image: `docker build -t kingsec:2.0.0 .`
- [ ] Push to registry
- [ ] Update documentation site
- [ ] Announce release

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Engineering | Abdul Mannan | 2026-07-30 |
| QA | Automated (3,253 tests) | 2026-07-30 |
| Security | Automated (ruff + manual audit) | 2026-07-30 |
