# KingSec

Local-first, AI-augmented **Attack Surface Management (ASM)** and **Vulnerability Management (VM)** for small and mid-sized businesses.

> **Status:** v2.0.0 — assessment engine complete: 6 wired scanners, honest coverage reporting, authorization-gated scans, PDF/HTML reports with executive scoring.

## Why KingSec?

- **Local-first & private.** Assessment data never leaves your machine unless you configure an integration; findings and reports are stored in a local SQLite database protected by filesystem permissions.
- **Unauthenticated external assessment.** KingSec examines what's reachable without logging in — it has no mechanism to authenticate to your application, so anything behind a login screen is out of scope. See "What KingSec Assesses," below.
- **Bring-your-own-AI-key.** AI credentials are user-supplied and stored encrypted at rest.
- **Professional frontend.** Built-in React SPA with Dashboard, Assessments, Findings, Reports, Settings, and Administration pages.
- **6 pluggable scanners.** Nmap, Nuclei, Nikto, FFUF, Gobuster, OWASP ZAP — reachable through every assessment profile, auto-detected and orchestrated. (Trivy, Semgrep, and Amass are also registered scanner plugins in the codebase but aren't wired into any current profile.)
- **Reports.** HTML and PDF, with executive scoring.
- **Honest by design.** No fake progress, no fear-selling, no paywalled critical findings.
- **Safe by default.** Authorization gate enabled by default. Server binds to 127.0.0.1.

## What KingSec Assesses

KingSec performs **unauthenticated** external security assessment: open ports and services, missing security headers, outdated software versions, and application-layer issues an unauthenticated visitor could find. It does not have a mechanism to log in to your application, so business-logic flaws, authorization bugs between user roles, and anything else reachable only once signed in are **not** examined by any assessment. A clean report means no unauthenticated issues were found — it says nothing about what sits behind your login screen.

## Quick Start

```bash
# Docker (recommended) — zero to first assessment in 5 minutes
docker build -t kingsec:2.0.0 .
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # copy the output
docker run -d --name kingsec -p 8765:8765 \
  -e KINGSEC_SECRETS__ENCRYPTION_KEY="<paste-the-generated-key>" \
  -v kingsec-data:/home/kingsec/.kingsec kingsec:2.0.0
# The API + Swagger UI are now at http://127.0.0.1:8765/docs
```

> **The web UI is a separate app.** This container serves the REST API
> only — there is no built-in frontend hosting yet. To use the browser UI,
> run the frontend separately: `cd frontend && npm install && npm run dev`,
> then open http://localhost:5173 (it proxies API calls to port 8765).
> `KINGSEC_SECRETS__ENCRYPTION_KEY` is mandatory — the server refuses to
> start without it, in every environment.

See [docs/QUICK_START.md](docs/QUICK_START.md) for the complete walkthrough.

## Documentation

| Guide | Description |
|-------|-------------|
| [docs/INSTALL.md](docs/INSTALL.md) | System requirements and installation (Docker, pip, Windows, Linux, macOS) |
| [docs/QUICK_START.md](docs/QUICK_START.md) | First assessment in under 15 minutes |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | End-user guide: assessments, findings, reports, settings |
| [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) | Administration: users, roles, backup, security hardening |
| [docs/SCANNER_GUIDE.md](docs/SCANNER_GUIDE.md) | Scanner installation, discovery, and troubleshooting |
| [docs/REPORTING_GUIDE.md](docs/REPORTING_GUIDE.md) | Report formats, executive scoring, findings interpretation |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Complete REST API endpoint reference |
| [docs/FAQ.md](docs/FAQ.md) | Frequently asked questions |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Product roadmap and planned features |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [docs/RELEASE_NOTES.md](docs/RELEASE_NOTES.md) | Current release notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development guide and contribution process |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [SECURITY.md](SECURITY.md) | Security policy and vulnerability reporting |

## Installation

### Docker (recommended)
```bash
docker build -t kingsec:2.0.0 .
cp .env.example .env
# Edit .env and uncomment/set KINGSEC_SECRETS__ENCRYPTION_KEY (required —
# the server refuses to start without it) plus the other ⚠️ REQUIRED values.
docker run -d --name kingsec --env-file .env -p 8765:8765 -v kingsec-data:/home/kingsec/.kingsec kingsec:2.0.0
```

### Docker Compose
```bash
cp .env.example .env
# Edit .env as above before starting.
docker compose up -d
```

### From source (pip)
KingSec is not (yet) published on PyPI — install from a repository checkout:
```bash
git clone https://github.com/kingusecurity/kingsec.git
cd kingsec
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install .
export KINGSEC_SECRETS__ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
kingsec-migrate
kingsec
```

See [docs/INSTALL.md](docs/INSTALL.md) for complete instructions including Windows, macOS, and scanner dependencies.

## Quick links

- **API:** http://127.0.0.1:8765/api/v1
- **Swagger UI:** http://127.0.0.1:8765/docs
- **Frontend (dev server, run separately — see above):** http://localhost:5173
- **Health check:** http://127.0.0.1:8765/api/v1/healthz/live

## Assessment Profiles

KingSec provides reusable **assessment profiles** that automatically select
the right scanners and configuration based on your goal. The operator chooses
a profile — KingSec handles the rest.

### Available profiles

| Profile | Scanners | Target Types | Duration | Best for |
|---|---|---|---|---|
| **Quick Host Scan** | Nmap | IP, Hostname | ~5 min | Fast port check on a single host |
| **Network Assessment** | Nmap, Nuclei | Network, IP, Hostname | ~30 min | Network range vulnerability sweep |
| **Web Application Scan** | Gobuster, FFUF, Nuclei, ZAP | URL | ~60 min | Comprehensive web app assessment |
| **API Assessment** | FFUF, Nuclei, ZAP | URL | ~45 min | REST/HTTP API security testing |
| **External Footprint** | Nmap | Hostname, IP | ~15 min | Attack surface discovery |
| **Full Assessment** | Nmap, Nuclei, Gobuster, FFUF, ZAP, Nikto | IP, Hostname, URL | ~60 min | Maximum coverage across all 6 reachable scanners |

> Nmap is also listed in the Web Application Scan profile but is always
> skipped for URL targets today (nmap's registered capabilities don't
> include `url`) — this is reported honestly as a coverage gap, not
> silently dropped. Semgrep, Trivy, and Amass were removed from every
> profile: KingSec's target model has no `repository`/`image`/`path`
> target type for them to run against yet.

### How profiles work

1. **Choose a profile** based on the type of assessment you need.
2. KingSec checks which scanners are installed and usable (via Scanner Discovery).
3. An **execution plan** is generated showing:
   - Which scanners will run
   - Which scanners are skipped (optional, not installed)
   - Which scanners are blocking (required, not installed)
   - Estimated duration
   - Any warnings
4. If a required scanner is missing, the assessment cannot start — a clear
   error explains what needs to be installed.
5. Optional scanners that are unavailable are simply skipped with a warning.

### API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/profiles` | List all assessment profiles |
| `GET` | `/api/v1/profiles/{profile_id}` | Single profile details |
| `POST` | `/api/v1/profiles/{profile_id}/plan` | Generate an execution plan |

The plan endpoint accepts:

```json
{
  "target": "10.0.0.5",
  "target_type": "ip_address"
}
```

And returns the full execution plan with scanner selections, warnings,
and a `can_proceed` flag.

### Profile compatibility by target type

| Target Type | Compatible Profiles |
|---|---|
| `ip_address` | Quick Scan, Network Scan, External Footprint, Full |
| `hostname` | Quick Scan, Network Scan, External Footprint, Full |
| `url` | Web Scan, API Scan, Full |
| `network` | Network Scan |

## Execution Progress Monitoring

When an assessment runs, KingSec tracks its lifecycle with granular **execution
phases** and **per-scanner progress**:

| Phase | Description | Progress |
|---|---|---|
| `pending` | Waiting to start | 0% |
| `preparing` | Setting up scan environment | 5% |
| `running_scanners` | Executing scanners (each tracked individually) | 5–85% |
| `correlating` | Combining and correlating findings | 85% |
| `reporting` | Generating report | 95% |
| `completed` / `failed` / `cancelled` | Terminal states | 100% |

### API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/assessments/{id}/execution/status` | Phase + per-scanner progress |
| `GET` | `/api/v1/assessments/{id}/execution/events` | Ordered lifecycle event log |
| `GET` | `/api/v1/assessments/{id}/execution/progress` | Overall progress percentage |
| `POST` | `/api/v1/assessments/{id}/execution/cancel` | Cancel a running execution |

The frontend **Assessment Detail** page shows a live progress panel when an
assessment is running, with a progress bar, per-scanner status cards, and a
collapsible event log. Running assessments auto-refresh every 3 seconds.

## Scanner Environment

KingSec has 9 scanner plugins registered in the codebase; 6 of them (Nmap,
Nuclei, Nikto, FFUF, Gobuster, OWASP ZAP) are reachable through the
assessment profiles above (Trivy, Semgrep, and Amass are registered but not
currently wired into any profile — see "Available profiles," above). The
**Scanner Discovery** system automatically detects which are installed,
validates their executables and required assets, and reports readiness
through the API and UI.

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
# 1. Install from a repository checkout (not yet published on PyPI)
git clone https://github.com/kingusecurity/kingsec.git && cd kingsec
pip install .

# 2. Set required environment variables
export KINGSEC_JWT__SECRET_KEY="your-production-secret"
export KINGSEC_SECRETS__ENCRYPTION_KEY="your-base64-32byte-key"   # mandatory — see .env.example

# 3. Run database migrations
kingsec-migrate

# 4. Start the server
kingsec

# The REST API + Swagger UI are now available at http://127.0.0.1:8765/docs
```

On Windows (PowerShell):
```powershell
git clone https://github.com/kingusecurity/kingsec.git
cd kingsec
pip install .
$env:KINGSEC_JWT__SECRET_KEY = "your-production-secret"
$env:KINGSEC_SECRETS__ENCRYPTION_KEY = "your-base64-32byte-key"   # mandatory
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
These two variables affect **migrations only** (read directly by `env.py`,
independent of the running server's own `Settings`). The running application
(`kingsec` / `python -m kingsec`) always uses SQLite at
`KINGSEC_STORAGE__DATA_DIR` — setting either of these does not change what
database the server itself connects to, and `KINGSEC_STORAGE__DATABASE_URL`
is not a recognized `Settings` field, so setting it will make the server
refuse to start (`ConfigError: ... Extra inputs are not permitted`).

| Variable | Purpose |
|---|---|
| `ALEMBIC_DATABASE_URL` | Migration-only database URL override (highest precedence for `alembic`/`kingsec-migrate`) |
| `KINGSEC_STORAGE__DATABASE_URL` | Migration-only PostgreSQL/external database URL, read only by the Alembic CLI — **not** honoured by the running server |
| `KINGSEC_STORAGE__DATA_DIR` | SQLite data directory used by both migrations and the running server (default: `~/.kingsec`) |

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

*KingSec v2.0.0 — [GitHub](https://github.com/kingusecurity/kingsec)*
