# KingSec

Local-first security assessment orchestration and professional reporting for small and mid-sized businesses.

> **Status:** v2.0.0 — authorization-gated assessment profiles, honest coverage reporting, and PDF/HTML reports with executive scoring.

## Why KingSec?

- **Local-first storage.** Findings and reports stay in a local SQLite database by default. Scanners still contact the authorized target, Amass may query public DNS/certificate-transparency sources, and configured AI providers or integrations receive the data their features require.
- **Unauthenticated external assessment.** KingSec examines what's reachable without logging in — it has no mechanism to authenticate to your application, so anything behind a login screen is out of scope. See "What KingSec Assesses," below.
- **Bring-your-own-AI-key.** AI credentials are user-supplied and stored encrypted at rest.
- **Professional frontend.** Built-in React SPA with Dashboard, Assessments, Findings, Reports, Settings, and Administration pages.
- **9 purpose-wired scanners.** Nmap, Nuclei, Nikto, FFUF, Gobuster, OWASP ZAP, Semgrep, Trivy, and Amass are selected only by profiles with compatible target types. Missing binaries are reported as unavailable, never as zero findings.
- **Reports.** HTML and PDF, with executive scoring.
- **Honest by design.** No fake progress, no fear-selling, no paywalled critical findings.
- **Safe by default.** Authorization gate enabled by default. Server binds to 127.0.0.1.

## What KingSec Assesses

KingSec's network and web profiles perform **unauthenticated** external security assessment: open ports and services, missing security headers, outdated software versions, and application-layer issues an unauthenticated visitor could find. Separate, explicit profiles can analyze a server-visible source path, a container image, or an authorized DNS domain. KingSec does not log in to applications, so business-logic flaws, authorization bugs between user roles, and anything reachable only after authentication remain out of scope. A clean report only speaks to the scanners and coverage shown in that report.

## Quick Start

```bash
# Docker (recommended)
cp .env.example .env
# Set all three required secrets in .env before continuing:
# KINGSEC_JWT__SECRET_KEY, KINGSEC_SECRETS__API_KEY_PEPPER,
# and KINGSEC_SECRETS__ENCRYPTION_KEY.
docker compose up -d --build
# Browser UI: http://127.0.0.1:8765/
# API docs:   http://127.0.0.1:8765/docs
```

> The Docker build bundles the React UI and the backend serves it same-origin.
> All three secrets named above are required for a production configuration.

See [docs/QUICK_START.md](docs/QUICK_START.md) for the complete walkthrough.

## Documentation

| Guide | Description |
|-------|-------------|
| [docs/INSTALL.md](docs/INSTALL.md) | System requirements and installation (Docker, pip, Windows, Linux, macOS) |
| [docs/QUICK_START.md](docs/QUICK_START.md) | Installation, administrator bootstrap, and first authorized assessment |
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
# Set all three required secrets, then run the container with the explicit
# container-only bind opt-in:
docker run -d --name kingsec --env-file .env \
  -e KINGSEC_SERVER__HOST=0.0.0.0 \
  -e KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true \
  -p 127.0.0.1:8765:8765 \
  -v kingsec-data:/home/kingsec/.kingsec kingsec:2.0.0
```

### Docker Compose
```bash
cp .env.example .env
# Edit .env as above before starting.
docker compose up -d --build
```

### From source (pip)
KingSec is not (yet) published on PyPI — install from a repository checkout:
```bash
git clone https://github.com/kingusecurity/kingsec.git
cd kingsec
./scripts/install.sh
# Windows PowerShell: powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

See [docs/INSTALL.md](docs/INSTALL.md) for complete instructions including Windows, macOS, and scanner dependencies.

## Quick links

- **API:** http://127.0.0.1:8765/api/v1
- **Swagger UI:** http://127.0.0.1:8765/docs
- **Bundled browser UI:** http://127.0.0.1:8765/
- **Frontend dev server (development only):** http://localhost:5173
- **Health and bootstrap state:** http://127.0.0.1:8765/api/v1/health

## Assessment Profiles

KingSec provides reusable **assessment profiles** that automatically select
the right scanners and configuration based on your goal. The operator chooses
a profile — KingSec handles the rest.

### Available profiles

| Profile | Scanners | Target Types | Duration | Best for |
|---|---|---|---|---|
| **Quick Host Scan** | Nmap | IP, Hostname | ~5 min | Fast port check on a single host |
| **Network Assessment** | Nmap, Nuclei | Network, IP, Hostname | ~30 min | Network range vulnerability sweep |
| **Web Application Scan** | Nmap, Gobuster, FFUF, Nuclei, ZAP | URL | ~60 min | Comprehensive web app assessment |
| **API Assessment** | FFUF, Nuclei, ZAP | URL | ~45 min | REST/HTTP API security testing |
| **External Footprint Mapping** | Nmap | Hostname, IP | ~15 min | Attack surface discovery |
| **Full Assessment** | Nmap, Nuclei, Gobuster, FFUF, ZAP, Nikto | IP, Hostname, URL | ~60 min | Broad network/web coverage; actual scanner selection depends on target type |
| **Source Code Assessment** | Semgrep, Trivy | Absolute source path | ~20 min | Static analysis and dependency/configuration checks |
| **Container Image Assessment** | Trivy | Container image | ~10 min | Image packages and configuration |
| **Domain Enumeration** | Amass | DNS domain | ~15 min | Authorized subdomain discovery |

> Profiles declare whether a scanner is required or optional. A missing
> required binary or asset blocks that profile; an unavailable optional scanner
> is recorded as a coverage gap. Nmap is currently listed in the URL-only Web
> Application profile but is reported as incompatible and skipped for that
> target type.
> Source paths are paths on the machine running KingSec, not paths on a remote
> browser workstation.

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
| `ip_address` | Quick Host Scan, Network Assessment, External Footprint Mapping, Full Assessment |
| `hostname` | Quick Host Scan, Network Assessment, External Footprint Mapping, Full Assessment |
| `url` | Web Application Scan, API Assessment, Full Assessment |
| `network` | Network Assessment |
| `domain` | Domain Enumeration |
| `source_path` | Source Code Assessment |
| `container_image` | Container Image Assessment |

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
| `completed` / `completed_with_gaps` / `failed` / `cancelled` | Terminal states | 100% |

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

KingSec has 9 scanner plugins registered in the codebase. All 9 are reachable
through an explicit compatible profile: the network/web profiles use Nmap,
Nuclei, Nikto, FFUF, Gobuster, and OWASP ZAP; the purpose-built source,
container, and domain profiles use Semgrep, Trivy, and Amass. The **Scanner
Discovery** system automatically detects which are installed, validates their
executables and required assets, and reports readiness through the API and UI.

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
| FFUF | `ffuf` | [GitHub Releases](https://github.com/ffuf/ffuf/releases) | `go install ...` | Configured wordlist |
| Gobuster | `gobuster` | [GitHub Releases](https://github.com/OJ/gobuster/releases) | `go install ...` | Configured wordlist |
| Trivy | `trivy` | `choco install trivy` | `apt install trivy` | Vulnerability DB recommended (`trivy image --download-db-only`) |
| Semgrep | `semgrep` | `pip install semgrep` | `pip install semgrep` | — |
| Amass | `amass` | [GitHub Releases](https://github.com/owasp-amass/amass/releases) | `go install ...` | — |
| OWASP ZAP | `zap` / `ZAP.exe` | [Official installer](https://www.zaproxy.org/download/) | Native package or official installer | Java runtime |

> **Note:** an unavailable required scanner blocks that profile at planning
> time. An unavailable optional scanner is recorded as a coverage gap; it is
> never presented as a successful zero-finding run.

For a source install, run `kingsec doctor` to check all nine scanners using the
same discovery and compatibility logic as the assessment planner. The base
Docker image does not bundle the external scanner executables, and binaries
installed only on the Docker host are not visible inside the container. Extend
the image with the scanners you are authorized to use, then run
`docker exec kingsec kingsec doctor` to verify that container environment.

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

This percentage is an inventory summary, not a readiness decision for a
specific assessment. Always review the execution plan for the chosen profile:
a high aggregate score can still coexist with a missing required scanner.

### Source-install scanner check

The one-shot installers above run the read-only scanner preflight automatically.
Run it again after adding or reconfiguring a scanner:

```bash
kingsec doctor
# Or without activating the installer-created virtual environment:
./.venv/bin/python -m kingsec doctor
```

On Windows, use `.\.venv\Scripts\python.exe -m kingsec doctor`.

## Database Migrations (Alembic)

KingSec uses Alembic for versioned database migrations. The migration chain is the source of truth for schema changes — never use `create_all()` in production.

### First-time setup
```bash
# Back up an existing SQLite database and stop the running service first.
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
