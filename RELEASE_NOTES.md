# KingSec v1.1.0 — Professional Report Center & Production Hardening

**Version:** 1.1.0  
**Release Date:** 2026-07-27  
**Status:** Production Ready

## Overview

KingSec is a local-first, AI-augmented Attack Surface Management (ASM) and Vulnerability Management (VM) platform designed for small and mid-sized businesses. v1.1.0 adds a professional Report Center frontend and hardens the production deployment with 11 security, correctness, and performance fixes.

## What's New in v1.1.0

### Report Center (Frontend)
- **Professional report management** with card grid layout, executive score rings, severity badges, and action indicators
- **Search & filter** — debounced text search, severity pill filters, multi-axis sort (newest, oldest, highest/lowest risk, A–Z)
- **Report preview drawer** — executive summary, risk severity bars, metadata panel (format, size, generated date, assessment ID)
- **Download & regenerate** with toast error feedback and loading states
- **Pagination** with page controls and result counters

### Production Hardening (10 fixes)
| Area | Fixes |
|---|---|
| **Auth** | Missing Bearer token in report regeneration API call |
| **Input validation** | Bounds clamping on all 6 paginated list endpoints (1–200) |
| **Data integrity** | SqlAlchemyUnitOfWork no longer rolls back after commit |
| **API correctness** | list_api_keys returns true total count + limit/offset fields |
| **UX** | FindingsPage no longer flashes spinner on filter change; Dashboard shows error state instead of "No reports" on failure; ExecutionProgressPanel only fetches events when expanded |
| **Cache** | Eliminated duplicate query keys between findings and dashboard hooks |
| **Error handling** | Silent catch blocks in ReportsPage now surface toast notifications |

## Upgrading from v1.0.x

Run database migrations:

```bash
alembic upgrade head
```

No breaking API changes. The Report Center is accessible at `/reports`.

## Known Issues

- Missing FK constraints on `JobRun` and `Artifact` models (planned for v1.2)
- No distributed job queue (single-node only; planned for v1.2)
- Scanner integration tests may timeout on slow CI runners
- `python -m kingsec` requires `alembic upgrade head` before first run

## Documentation

- Full README: [README.md](README.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: [SECURITY.md](SECURITY.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
