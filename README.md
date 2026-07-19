# KingSec

Local-first, AI-augmented **Attack Surface Management (ASM)** and **Vulnerability Management (VM)** for small and mid-sized businesses.

> **Status:** Release Candidate 1 — a production-grade security assessment platform with persistence, job management, report generation/multi-format export, scanner orchestration, and AI-augmented enrichment. Built on Clean Architecture (Hexagonal).

## Principles baked into the foundation
- **Local-first & private.** Runs on the user's machine; the web server binds to `127.0.0.1` by default.
- **Bring-your-own-AI-key.** AI credentials are user-supplied and never leave the machine or the repository.
- **Honest by design.** No fake progress, no fear-selling, no paywalled critical findings.
- **Safe by default.** An authorization gate guards any active scanning and is enabled by default.

## Architecture
Hexagonal (ports & adapters). The pure core (`domain`, `application`) is delivery-agnostic; everything external plugs in through ports. See [`docs/FOUNDATION.md`](docs/FOUNDATION.md) for the full blueprint and [`docs/adr/`](docs/adr/) for recorded decisions.

## Quick start (development)
```bash
# 1. Install uv (https://docs.astral.sh/uv/) - the recommended environment manager
# 2. Create the environment and install runtime + dev dependencies, install hooks
make install
# 3. Run every quality gate (lint, types, architecture, security, tests)
make check
```
Run `make help` to list all developer tasks.

## Database Migrations (Alembic)

KingSec uses Alembic for versioned database migrations. The migration chain is the source of truth for schema changes — never use `create_all()` in production.

### First-time setup
```bash
# Apply all migrations to create the schema
alembic upgrade head
```

> **Startup validation:** The application validates that the database has been migrated at startup. If `alembic_version` is missing, it raises `RuntimeError` with instructions to run `alembic upgrade head`. The application will NOT call `create_all()` — use Alembic exclusively for schema management.

### Common commands
```bash
# Apply all pending migrations
alembic upgrade head

# Roll back one migration
alembic downgrade -1

# Roll back to the beginning
alembic downgrade base

# Show current migration version
alembic current

# Show migration history
alembic history --verbose

# Auto-generate a migration after model changes
alembic revision --autogenerate -m "description of changes"

# Create an empty migration (manual SQL)
alembic revision -m "description of changes"
```

### Environment variables
| Variable | Purpose |
|---|---|
| `ALEMBIC_DATABASE_URL` | Override database URL (highest precedence) |
| `KINGSEC_STORAGE__DATABASE_URL` | PostgreSQL / external database URL |
| `KINGSEC_STORAGE__DATA_DIR` | SQLite data directory (default: `~/.kingsec`) |

### Troubleshooting
- **"No 'script_location' key found"**: Run commands from the project root (`kingsec/`).
- **"No changes detected" after model change**: Ensure the model is imported in `env.py` (it loads `models.py` directly via `importlib.util`).
- **SQLite foreign key errors**: The engine enables `PRAGMA foreign_keys=ON` automatically.
- **Downgrade leaves `alembic_version` table**: This is expected — Alembic tracks its version in this table.

## Layout
See [`docs/FOUNDATION.md`](docs/FOUNDATION.md) sections 2-3 for the full folder tree and the rationale for each directory.

## Security
Found a vulnerability? Please read [`SECURITY.md`](SECURITY.md).

## License
Proprietary. All rights reserved. See [`LICENSE`](LICENSE).
