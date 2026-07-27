# KingSec

Local-first, AI-augmented **Attack Surface Management (ASM)** and **Vulnerability Management (VM)** for small and mid-sized businesses.

> **Status:** v1.0.0 — a production-grade security assessment platform with persistence, job management, report generation/multi-format export, scanner orchestration (Nuclei, Nmap, Nikto, Trivy, OWASP ZAP, Semgrep, Amass, Gobuster, ffuf), and AI-augmented enrichment. Built on Clean Architecture (Hexagonal).

## Principles baked into the foundation
- **Local-first & private.** Runs on the user's machine; the web server binds to `127.0.0.1` by default.
- **Bring-your-own-AI-key.** AI credentials are user-supplied and never leave the machine or the repository.
- **Honest by design.** No fake progress, no fear-selling, no paywalled critical findings.
- **Safe by default.** An authorization gate guards any active scanning and is enabled by default.

## Architecture
Hexagonal (ports & adapters). The pure core (`domain`, `application`) is delivery-agnostic; everything external plugs in through ports. See [`docs/FOUNDATION.md`](docs/FOUNDATION.md) for the full blueprint and [`docs/adr/`](docs/adr/) for recorded decisions.

## Quick start (development)

### Linux / macOS
```bash
# 1. Install uv (https://docs.astral.sh/uv/) — the recommended environment manager
# 2. Create the environment and install runtime + dev dependencies
make install
# 3. Run every quality gate (lint, types, architecture, security, tests)
make check
```

### Windows
```batch
# 1. Ensure Python 3.11+ is installed
# 2. Install dependencies
make.bat install
# 3. Run quality gates
make.bat check
```

Run `make help` (Linux/macOS) or `make.bat help` (Windows) to list all developer tasks.

### First administrator
The very first user to register is automatically granted the **Administrator** role.
Every subsequent user receives **Viewer** (least privilege).

```bash
# Register the first user — this account becomes Administrator:
curl -X POST http://127.0.0.1:8765/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"MySecurePass1"}'
```

### Recovery CLI
If all administrators are lost, use the bootstrap CLI (requires shell access to the container):

```bash
kingsec-bootstrap --username admin --password "$(openssl rand -base64 32)" --email admin@example.com
```

On Windows:
```batch
kingsec-bootstrap --username admin --password "YourGeneratedPassword" --email admin@example.com
```

## Frontend
KingSec ships as a REST API only. Community frontends are listed at [kingusecurity/kingsec-frontends](https://github.com/kingusecurity/kingsec-frontends).

## Production deployment

### Docker (recommended)
```bash
# 1. Build the image
docker build -t kingsec:1.0.0 .

# 2. Create a .env file from the template
cp .env.example .env
# Edit .env with your production values (especially KINGSEC_JWT__SECRET_KEY)

# 3. Run the container
docker run -d \
  --name kingsec \
  --env-file .env \
  -p 8765:8765 \
  -v kingsec-data:/home/kingsec/.kingsec \
  kingsec:1.0.0
```

### Docker Compose
```bash
# 1. Create a .env file from the template
cp .env.example .env

# 2. Start the service
docker compose up -d

# 3. View logs
docker compose logs -f
```

## Scanner Environment

KingSec supports 9 scanning engines. The **Scanner Discovery** system
automatically detects which are installed, validates their executables and
required assets, and reports readiness through the API and UI.

### Quick check

```bash
# Via the API (authenticated)
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8765/api/v1/scanners/health
```

Or open the **Live Monitoring** page in the frontend UI to see the Scanner
Health panel — install status, version, warnings, and health score at a glance.

### Prerequisites

| Scanner | Binary | Windows | Linux | Required Assets |
|---|---|---|---|---|
| Nmap | `nmap` | `choco install nmap` | `apt install nmap` | — |
| Nuclei | `nuclei` | [GitHub Releases](https://github.com/projectdiscovery/nuclei/releases) | `go install ...` | Nuclei templates (`nuclei -update-templates`) |
| Nikto | `nikto` | [GitHub Releases](https://github.com/sullo/nikto/releases) | `apt install nikto` | — |
| FFUF | `ffuf` | [GitHub Releases](https://github.com/ffuf/ffuf/releases) | `go install ...` | — |
| Gobuster | `gobuster` | [GitHub Releases](https://github.com/OJ/gobuster/releases) | `go install ...` | — |
| Trivy | `trivy` | `choco install trivy` | `apt install trivy` | Vulnerability DB (`trivy image --download-db-only`) |
| Semgrep | `semgrep` | `pip install semgrep` | `pip install semgrep` | — |
| Amass | `amass` | [GitHub Releases](https://github.com/owasp-amass/amass/releases) | `go install ...` | — |
| OWASP ZAP | `zap` | [Download](https://www.zaproxy.org/download/) | `docker run ...` | — |

> **Note:** Scanners not installed are simply skipped during scans. KingSec
> remains fully operational with whatever subset is available.

### Auto-discovery

On startup and periodically, KingSec checks:

1. **Executable** — looked up via `PATH`, Chocolatey (`C:\ProgramData\chocolatey\bin`),
   Scoop (`~/scoop/apps`), WinGet (`~/AppData/Local/Microsoft/WinGet/Links`),
   `/snap/bin`, `/usr/local/bin`, and standard install locations.
2. **Version** — extracted from `--version` / `-version` output.
3. **Required assets** — template directories, vulnerability databases, wordlists
   are checked for existence.
4. **Usability** — a scanner is flagged *usable* only when its binary and all
   non-optional assets are present.

### API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/scanners` | List all scanners with status |
| `GET` | `/api/v1/scanners/health` | Aggregate health score + per-scanner status |
| `GET` | `/api/v1/scanners/{scanner_id}` | Detailed status for one scanner |

All endpoints require authentication. No installation or modification is
performed — they are read-only diagnostics.

### Health score

The health score is computed as:

    health_score = (usable_scanners / total_scanners) × 100

| Score | Interpretation |
|---|---|
| 80–100% | All critical scanners operational |
| 50–79% | Some scanners need attention |
| < 50% | Most scanners not ready |

### Direct installation
```bash
# 1. Install via pip (once published)
pip install kingsec

# 2. Set required environment variables
export KINGSEC_JWT__SECRET_KEY="your-production-secret"
export KINGSEC_SECRETS__ENCRYPTION_KEY="your-base64-32byte-key"

# 3. Run database migrations
kingsec-migrate

# 4. Start the server
kingsec

# The API is now available at http://127.0.0.1:8765
```

On Windows:
```batch
pip install kingsec
set KINGSEC_JWT__SECRET_KEY=your-production-secret
kingsec-migrate
kingsec
```

## Database Migrations (Alembic)

KingSec uses Alembic for versioned database migrations. The migration chain is the source of truth for schema changes — never use `create_all()` in production.

### First-time setup
```bash
# From a repository checkout (alembic.ini is in the project root):
alembic upgrade head

# From a pip-installed package (alembic.ini is bundled in the wheel):
kingsec-migrate
```

> **Startup validation:** The application validates that the database has been migrated at startup. If `alembic_version` is missing, it raises `RuntimeError` with instructions to run `alembic upgrade head`. The application will NOT call `create_all()` — use Alembic exclusively for schema management.

### Common commands (from a repository checkout)
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
- **"No 'script_location' key found"**: Run commands from the project root (`kingsec/`) or use `kingsec-migrate` if installed via pip.
- **"No changes detected" after model change**: Ensure the model is imported in `env.py` (it loads `models.py` directly via `importlib.util`).
- **SQLite foreign key errors**: The engine enables `PRAGMA foreign_keys=ON` automatically.
- **Downgrade leaves `alembic_version` table**: This is expected — Alembic tracks its version in this table.

## Layout
See [`docs/FOUNDATION.md`](docs/FOUNDATION.md) sections 2-3 for the full folder tree and the rationale for each directory.

## Author
KingSec was created and is maintained by **Abdul Mannan**.

## Support
For support, feature requests, or general inquiries: **kingusecurity@gmail.com**

## Security
Found a vulnerability? Please read [`SECURITY.md`](SECURITY.md) or report it directly to **kingusecurity@gmail.com**.

## License
Proprietary. All rights reserved. See [`LICENSE`](LICENSE).

---

*KingSec v1.0.0 — [GitHub](https://github.com/kingusecurity/kingsec)*
