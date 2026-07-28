# KingSec v1.1.0 — GitHub Release Content

**Version:** 1.1.0  
**Tag:** `v1.1.0`  
**Release Date:** 2026-07-27

---

## Release Title

KingSec v1.1.0 — Professional Report Center & Commercial Launch

---

## Release Description

We are excited to announce KingSec v1.1.0, the Professional Report Center release. This version ships with a rich React frontend for report management, comprehensive commercial documentation, and production hardening across auth, data integrity, and performance.

### What's New

#### Professional Report Center

The new Report Center provides a complete report management experience:

- Card grid layout with executive score rings, severity badges, and action indicators
- Debounced text search across target, assessment ID, and verdict
- Severity filter pills for quick narrowing
- Multi-axis sort (newest, oldest, highest/lowest risk, A-Z, Z-A)
- Slide-out preview drawer with full executive summary, risk bars, and metadata
- One-click download and report regeneration
- Pagination with result counters

#### Frontend Improvements

The frontend now includes live execution progress tracking with per-scanner status cards, collapsible event log (lazy-loaded only when expanded), and improved error handling across all pages.

#### Production Hardening

11 security and correctness fixes:

- **Auth:** Missing Bearer token in report regeneration API calls is now injected
- **Input validation:** All 6 paginated list endpoints enforce limit bounds (1-200)
- **Data integrity:** SqlAlchemyUnitOfWork no longer performs rollback after commit
- **API correctness:** list_api_keys now returns true total count (not len(items)) plus limit/offset fields
- **Cache:** Eliminated duplicate query keys between findings and dashboard hooks
- **UX fixes:** FindingsPage no longer flashes spinner on filter change; Dashboard shows error state instead of "No reports" on API failure; catch blocks surface toast notifications

#### Commercial Launch Kit

Complete documentation suite for commercial distribution:

- Installation guide (INSTALL.md)
- Quick start guide (QUICK_START.md)
- User guide (USER_GUIDE.md)
- Administrator guide (ADMIN_GUIDE.md)
- Scanner guide (SCANNER_GUIDE.md)
- Reporting guide (REPORTING_GUIDE.md)
- API reference (API_REFERENCE.md)
- FAQ and Troubleshooting guides
- Product roadmap (ROADMAP.md)
- Website copy, product messaging, branding guidelines
- Commercial templates (proposals, quotes, onboarding)
- Demo dataset and screenshot checklist

### Upgrading from v1.0.x

```bash
# Pull the new image
docker pull kingsec:1.1.0

# Stop and remove the old container
docker stop kingsec
docker rm kingsec

# Run the new version with the same data volume
docker run -d --name kingsec --env-file .env -p 8765:8765 -v kingsec-data:/home/kingsec/.kingsec kingsec:1.1.0
```

Run database migrations on startup (automatic in Docker; manual with `alembic upgrade head` for pip installations).

### Breaking Changes

None. The API is fully backward-compatible with v1.0.x. No database schema changes required.

### Known Limitations

- Missing FK constraints on JobRun and Artifact models (planned for v1.2)
- No distributed job queue (single-node only; planned for v1.2)
- Scanner integration tests may timeout on slow CI runners
- python -m kingsec requires alembic upgrade head before first run
- 4 no-op Alembic migration files from initial schema generation

### Installation

**Docker (recommended):**

```bash
docker build -t kingsec:1.1.0 .
cp .env.example .env
docker run -d --name kingsec --env-file .env -p 8765:8765 -v kingsec-data:/home/kingsec/.kingsec kingsec:1.1.0
```

**Docker Compose:**

```bash
cp .env.example .env
docker compose up -d
```

**Direct pip:**

```bash
pip install kingsec
kingsec-migrate
KINGSEC_JWT__SECRET_KEY="your-secret" kingsec
```

### Assets

- `kingsec-1.1.0-py3-none-any.whl`
- `kingsec-1.1.0.tar.gz`
- `Source code` (zip, tar.gz)

### Checksums

```
[sha256sum of kingsec-1.1.0-py3-none-any.whl]
[sha256sum of kingsec-1.1.0.tar.gz]
```

### Contributors

- Abdul Mannan

---

**Full Changelog:** https://github.com/kingusecurity/kingsec/compare/v1.0.1...v1.1.0

**Documentation:** https://github.com/kingusecurity/kingsec/blob/v1.1.0/README.md
