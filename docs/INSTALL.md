# KingSec v2.0.0 Installation Guide

Author: Abdul Mannan
Contact: kingusecurity@gmail.com
GitHub: https://github.com/kingusecurity/kingsec

---

## Important: what this guide covers

KingSec ships two independent pieces that are installed and run separately:

1. **The backend** — a FastAPI REST API + SQLite/PostgreSQL database. This
   is what `docker run`, `kingsec-migrate`, and `kingsec` set up and start.
   It exposes the API and an interactive Swagger UI at `/docs`.
2. **The frontend** — a React SPA in `frontend/`. It is a separate Node.js
   project with its own dependencies. There is currently no built-in way
   for the backend to serve the frontend, and no bundled Docker image that
   includes it — you always run it separately (`npm run dev` for
   development, or build it and host `frontend/dist/` with any static
   file server for production).

If you only need the API (automation, CI, scripting), you can stop after
the backend section. If you want the browser UI, do both.

---

## System Requirements

### Minimum Requirements

- CPU: 2 cores, 2.0 GHz or higher
- RAM: 4 GB
- Disk: 10 GB free space
- Python: 3.11, 3.12, or 3.13 (declared-supported range; the project has
  also been run successfully on 3.14, but that is not yet an officially
  declared target)
- Node.js: 20.x or newer (only needed if you plan to run the frontend)
- Docker: 24.0 or higher (only needed for the Docker installation path)

### Recommended Requirements

- CPU: 4 cores, 2.5 GHz or higher
- RAM: 8 GB (16 GB if running several scanners concurrently)
- Disk: 50 GB SSD
- Python: 3.12
- Docker: 26.0 or higher with Docker Compose v2

### Supported Operating Systems

KingSec has no OS-specific code paths beyond scanner-executable discovery
(see the Scanner Dependency table in `README.md`). It has been verified in
this audit on Windows 10/11; the general requirement is any OS with a
supported Python (and, for Docker installs, any OS Docker Desktop/Engine
supports).

---

## Docker Installation (Recommended)

There is **no published Docker Hub image**. You build the image locally
from the `Dockerfile` in this repository.

### Step 1: Install Docker

**Windows:** Download and install Docker Desktop from
https://docs.docker.com/desktop/setup/install/windows-install/. Ensure the
WSL 2 backend is enabled during installation.

**Ubuntu / Debian**
```bash
sudo apt update
sudo apt install -y docker.io docker-compose-v2
sudo systemctl enable --now docker
```

**macOS:** Download and install Docker Desktop from
https://docs.docker.com/desktop/setup/install/mac-install/

### Step 2: Build the Image

From the repository root (where `Dockerfile` lives):
```bash
docker build -t kingsec:2.0.0 .
```
This is a multi-stage build (Python 3.12-slim base, builds a wheel, then
installs it into a slim runtime image as a non-root user). It takes a few
minutes on first build.

### Step 3: Configure Required Secrets

```bash
cp .env.example .env
```
Open `.env` and uncomment/set at minimum `KINGSEC_SECRETS__ENCRYPTION_KEY`
— **the server refuses to start without it, with no exceptions** (see
"Environment Variables" below). Generate one with:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Also set `KINGSEC_JWT__SECRET_KEY` and `KINGSEC_SECRETS__API_KEY_PEPPER`
for anything beyond local experimentation — they have insecure built-in
defaults that let the server start, but must not be used in production.

### Step 4: Run the Container

```bash
docker run -d \
  --name kingsec \
  --restart unless-stopped \
  --env-file .env \
  -p 127.0.0.1:8765:8765 \
  -v kingsec-data:/home/kingsec/.kingsec \
  kingsec:2.0.0
```

On Windows (PowerShell), the command is identical — Docker Desktop
accepts the same syntax; just run it inside PowerShell without the
trailing `\` line continuations, or use `` ` `` in place of `\`:
```powershell
docker run -d `
  --name kingsec `
  --restart unless-stopped `
  --env-file .env `
  -p 127.0.0.1:8765:8765 `
  -v kingsec-data:/home/kingsec/.kingsec `
  kingsec:2.0.0
```

Notes on the exact flags used above (all verified against the real
`Dockerfile`):
- The named volume `kingsec-data` mounts to `/home/kingsec/.kingsec` —
  this is the container's real data directory (there is no `/app/data`).
- Binding to `127.0.0.1` on the host keeps the API off your network by
  default even though the container itself listens on `0.0.0.0` inside
  its own isolated network namespace.

### Step 5: Verify the Container is Running

```bash
docker ps --filter name=kingsec
docker logs kingsec --tail 50
curl http://127.0.0.1:8765/api/v1/health
```
Expected health response: `{"status":"ok"}`.

If the container exits immediately, `docker logs kingsec` will show a
`ConfigError` naming the missing environment variable — this is almost
always `KINGSEC_SECRETS__ENCRYPTION_KEY` not being set.

---

## Docker Compose Installation

The repository already includes a working `docker-compose.yml`. You do
not need to write your own.

```bash
cp .env.example .env
# Edit .env: set KINGSEC_SECRETS__ENCRYPTION_KEY (required) and the other
# ⚠️ REQUIRED values for anything beyond local experimentation.
docker compose up -d
docker compose logs -f      # follow logs
docker compose ps           # check status
docker compose down         # stop
```

The bundled compose file builds the image from the local `Dockerfile`,
binds the API to `127.0.0.1:8765`, and stores data in a named volume —
you do not need to create one yourself.

---

## Direct (non-Docker) Installation

Use this method for development, air-gapped environments, or when Docker
is not available. **KingSec is not published on PyPI** — `pip install
kingsec` will fail. Install from a repository checkout instead.

### Step 1: Clone the Repository

```bash
git clone https://github.com/kingusecurity/kingsec.git
cd kingsec
```

### Step 2: Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### Step 3: Install KingSec

```bash
pip install .
```
This builds and installs the `kingsec` wheel and its runtime dependencies
(FastAPI, SQLAlchemy, Alembic, WeasyPrint, etc.) and creates three console
scripts in the venv: `kingsec`, `kingsec-migrate`, `kingsec-bootstrap`.
Verified in this audit: a clean venv, `pip install .`, and the resulting
wheel install every dependency correctly with no manual intervention.

For development (linting, type-checking, tests) install the extra dev
tooling instead:
```bash
pip install -e ".[dev]"
```

### Step 4: Configure Required Secrets

```bash
cp .env.example .env
```
Edit `.env` and set `KINGSEC_SECRETS__ENCRYPTION_KEY` (mandatory — see
above). Then load it into your shell, or export the variables directly:

```bash
export KINGSEC_SECRETS__ENCRYPTION_KEY="$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
```

On Windows (PowerShell):
```powershell
$env:KINGSEC_SECRETS__ENCRYPTION_KEY = (python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
```

> **Note:** there is no `kingsec db init` or `kingsec start --host/--port`
> command. The real CLI has exactly three entry points: `kingsec`
> (starts the server), `kingsec-migrate` (runs Alembic migrations), and
> `kingsec-bootstrap` (creates a recovery admin account — see
> "Recovering Admin Access" below). Host/port are configured via
> `KINGSEC_SERVER__HOST` / `KINGSEC_SERVER__PORT` environment variables,
> not command-line flags.

### Step 5: Initialize the Database

```bash
kingsec-migrate
```
This applies every Alembic migration to a fresh SQLite database at
`~/.kingsec/kingsec.db` by default (override with
`KINGSEC_STORAGE__DATA_DIR`). Verified: running this against a brand-new,
empty data directory applies the entire migration chain cleanly.

### Step 6: Start KingSec

```bash
kingsec
```
The service runs in the foreground, logging to stdout. Stop it with
Ctrl+C. For a background/production run, use a process manager (systemd,
supervisord, NSSM on Windows) — see below.

The API is now at `http://127.0.0.1:8765/api/v1`, and interactive Swagger
docs are at `http://127.0.0.1:8765/docs`. There is no web UI at this URL
— see "Running the Frontend" below for that.

### systemd Service File (Linux)

Create `/etc/systemd/system/kingsec.service`:
```ini
[Unit]
Description=KingSec ASM and VM Platform
After=network.target

[Service]
Type=simple
User=kingsec
WorkingDirectory=/opt/kingsec
Environment="PATH=/opt/kingsec/.venv/bin"
Environment="KINGSEC_SECRETS__ENCRYPTION_KEY=<your-generated-key>"
Environment="KINGSEC_JWT__SECRET_KEY=<your-production-secret>"
ExecStart=/opt/kingsec/.venv/bin/kingsec
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```
Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now kingsec
```

---

## Running the Frontend

The web UI is a separate React app under `frontend/` and is never started
by the `kingsec` command.

### Development

```bash
cd frontend
npm install
npm run dev
```
Open **http://localhost:5173**. The Vite dev server proxies every `/api`
request to `http://127.0.0.1:8765` (hardcoded in `frontend/vite.config.ts`
— there is no environment variable to change this; edit the file
directly if you need a different backend port). The backend must already
be running for the proxy to work. Verified in this audit: `npm run dev`
starts cleanly and serves the SPA on port 5173.

### Production

```bash
cd frontend
npm install
npm run build
```
This produces a static SPA in `frontend/dist/`. There is currently no
built-in server for it — host it with any static file server (nginx, a
CDN, `npx serve`, etc.) that supports SPA fallback routing (serving
`index.html` for unmatched routes), and ensure that host can reach the
backend at the `/api/v1` path (typically via a reverse-proxy rule that
forwards `/api/*` to the backend process). See `frontend/README.md`'s
"Production Deployment" section for a worked nginx example.

---

## Windows-Specific Notes

### Path Configuration

Ensure Python 3.11+ is on your `PATH`. Verify with:
```
python --version
pip --version
```

### Chocolatey / Scoop

```powershell
choco install python --version 3.12
choco install docker-desktop
```
or
```powershell
scoop bucket add extras
scoop install python
scoop install docker
```

### PDF Report Generation Requires GTK3

Report generation uses WeasyPrint, which needs system-level GTK/Pango/
Cairo libraries that `pip install` does **not** provide on Windows.
Without them, generating a PDF report fails with a `500` error
(`KS-REPORT-001`) and the server log shows "WeasyPrint could not import
some external libraries." **Verified in this audit**: a fresh, correctly
migrated, correctly started install reproduces this exact failure until
the GTK3 runtime is installed.

Fix: download and run the GTK3 runtime installer from
https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases,
then restart your terminal (and KingSec) so the updated `PATH` takes
effect. This only affects direct/non-Docker installs — the Docker image
already bundles the required libraries.

### Windows Firewall

Only needed if you bind to `0.0.0.0` (not the default, and not
recommended without a reverse proxy):
```powershell
New-NetFirewallRule -DisplayName "KingSec API" -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow
```

---

## Environment Variables

`.env.example` is the authoritative, fully-commented reference — copy it
to `.env` and read the inline comments. The convention is
`KINGSEC_<GROUP>__<FIELD>` (**double** underscore between group and
field; this is not a typo). The variables that actually gate startup, as
verified against the running application in this audit:

| Variable | Required? | Verified behavior if unset |
|---|---|---|
| `KINGSEC_SECRETS__ENCRYPTION_KEY` | **Always required** | Server raises `ConfigError` and exits immediately on startup, in every environment including local development. There is no "disabled" mode. |
| `KINGSEC_JWT__SECRET_KEY` | Required for production | Has an insecure built-in default; the server starts without it, but must not be run that way in production. |
| `KINGSEC_SECRETS__API_KEY_PEPPER` | Required for production | Same as above — has an insecure default (`CHANGE-ME-IN-PRODUCTION-DO-NOT-USE-DEFAULT`). |
| `KINGSEC_SERVER__HOST` | Optional | Defaults to `127.0.0.1` (loopback-only). |
| `KINGSEC_SERVER__PORT` | Optional | Defaults to `8765`. |
| `KINGSEC_SERVER__ALLOW_EXTERNAL_BIND` | Optional | Must be `true` to bind to `0.0.0.0`; otherwise the server raises a startup error rather than silently exposing itself. |
| `KINGSEC_STORAGE__DATA_DIR` | Optional | Defaults to `~/.kingsec` (SQLite). |
| `KINGSEC_STORAGE__DATABASE_URL` | Optional | Overrides `DATA_DIR` for PostgreSQL or an external database. |
| `ALEMBIC_DATABASE_URL` | Optional | Overrides the database URL for `kingsec-migrate` specifically; defaults to the same database the app uses. |

Generate the two secret values with:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # KINGSEC_SECRETS__ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_urlsafe(64))"                                # KINGSEC_JWT__SECRET_KEY / API_KEY_PEPPER
```

---

## Scanner Dependency Installation

KingSec uses pluggable scanners. Install them according to your
assessment needs — see the table in `README.md`'s "Scanner Environment"
section for the exact per-OS install commands and required assets. None
of the 9 scanners are mandatory: KingSec starts and runs fine with zero
scanners installed, it just skips any assessment that requires one that
is missing.

**Note:** After installing a scanner, restart KingSec so scanner
discovery re-detects it.

---

## Database Migrations

KingSec uses Alembic exclusively for schema management — the application
never calls `create_all()`. There is no automatic migration-on-startup;
you must run `kingsec-migrate` (or, from a repo checkout, `alembic
upgrade head`) yourself before first start and after every upgrade.

```bash
# Apply all pending migrations
kingsec-migrate                       # pip install (uses the packaged alembic.ini)
alembic upgrade head                  # repo checkout — run from the repo root; the
                                       # root-level alembic.ini already points at
                                       # src/kingsec/alembic, no -c flag needed

# Show current migration version
alembic current

# Show migration history
alembic history --verbose
```

**Startup validation:** the application checks that migrations have been
applied at startup and raises `RuntimeError` with clear instructions if
not. If you see this, run the command above before starting the server
again.

There is no `kingsec db backup/restore/rollback` command. For SQLite,
back up by copying the database file directly (default:
`~/.kingsec/kingsec.db`) while the server is stopped, or use the
application's own Backup feature (`POST /api/v1/backups`) while it is
running.

---

## Recovering Admin Access

If every admin account is lost, use the bundled recovery CLI (this exists
and works — verified against the source — but was undocumented in
earlier releases of this guide):
```bash
kingsec-bootstrap --username <name> --password <secret>
```
This refuses to run if an admin already exists, and refuses to run if
migrations have not been applied.

---

## First-Run Setup

### Step 1: Access the API

Open `http://127.0.0.1:8765/docs` for interactive Swagger UI, or run the
frontend (see "Running the Frontend" above) and open
`http://localhost:5173` for the browser UI.

### Step 2: Create the First Admin Account

Register via the UI's "Register" link, or directly against the API:
```bash
curl -X POST http://127.0.0.1:8765/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"<a strong password>"}'
```
**Verified in this audit:** the first user ever registered is
automatically granted the Admin role; every subsequent registration
defaults to Viewer until an admin promotes them.

### Step 3: Verify Scanner Connectivity

Check `GET /api/v1/scanners/health` (via Swagger UI, curl with your
bearer token, or the frontend's Live Monitoring page) to see which
scanners were auto-detected.

---

## Verification Steps

After installation, confirm KingSec is operational — every command below
was executed against a real, freshly-installed instance during this
audit.

### Health Check
```bash
curl http://127.0.0.1:8765/api/v1/health
```
Verified response: `{"status":"ok"}`. (There is no `/api/health` — note
the `/v1/` — and no separate version-check endpoint; the running
version is only visible in the startup log line `application composed
... version=2.0.0` or via `pip show kingsec` for a real, non-editable
install.)

### Swagger UI
```bash
curl -o /dev/null -s -w "%{http_code}\n" http://127.0.0.1:8765/docs
```
Verified: returns `200`.

### Docker Logs
```bash
docker logs kingsec --tail 50
```
Look for `application started` and `Uvicorn running on
http://0.0.0.0:8765`.

---

## Troubleshooting Common Install Issues

### Server exits immediately with `ConfigError`
`KINGSEC_SECRETS__ENCRYPTION_KEY` (or occasionally another `⚠️ REQUIRED`
variable) is unset. See "Environment Variables" above.

### `pip install kingsec` fails / package not found
There is no published PyPI package. Clone the repository and run `pip
install .` from the checkout instead.

### `pip show kingsec` reports an old version after pulling updates
This is a known `pip`/editable-install quirk, not a KingSec bug: if you
installed with `pip install -e .`, the cached package metadata does not
automatically refresh when `pyproject.toml`'s version changes. Re-run
`pip install -e .` (or `pip install -e ".[dev]"`) after pulling updates
to refresh it. The running application's own reported version (in logs,
and everywhere in the UI) is unaffected by this and is always correct.

### Port 8765 Already in Use
```bash
docker run -d -p 127.0.0.1:18765:8765 --env-file .env kingsec:2.0.0
```
or set `KINGSEC_SERVER__PORT` for a direct install.

### Permission Denied on Volume Mounts (Linux)
```bash
sudo chown -R 1000:1000 <your-bind-mounted-data-dir>
```
(The container's `kingsec` user is UID 1000. This only applies if you
bind-mount a host directory instead of using the named `kingsec-data`
volume shown above.)

### PDF Report Generation Fails on Windows / Linux / macOS (direct install)
See "PDF Report Generation Requires GTK3" above, and the expanded entry
in `TROUBLESHOOTING.md`.

### Scanners Not Detected
- Verify the scanner is on `PATH`: `where nmap` (Windows) / `which nmap`
  (Linux/macOS).
- Restart KingSec after installing a new scanner.
- Check `GET /api/v1/scanners/health` for the exact reason (missing
  binary vs. missing required asset).

### Web UI shows nothing / 404 at port 8765
This is expected — the backend does not serve the frontend. See "Running
the Frontend" above.
