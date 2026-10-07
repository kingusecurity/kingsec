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
(see the Scanner Dependency table in `README.md`); the general requirement
is any OS with a supported Python (and, for Docker installs, any OS Docker
Desktop/Engine supports).

**Correction — what was actually tested on Windows:** an earlier version of
this guide claimed Windows 10/11 was "verified in this audit." That
overstated it. What was actually tested was Docker Desktop's **Linux
container** running on a Windows 10/11 host (the "Docker Installation"
section above) — the container itself is Linux; Windows only hosts it. The
**Direct (non-Docker) Installation** section below, run natively against a
real Windows Python install with no container involved, remains **NOT
TESTED**. If you follow the native path on Windows and hit something this
guide doesn't cover, that is expected, not a sign you did something wrong —
please report it.

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

### Before you expose this beyond your own machine

By default, `docker-compose.yml` publishes the port as
`"127.0.0.1:8765:8765"` — reachable only from the host KingSec is running
on, not from your network. Inside the container the server binds to
`0.0.0.0`, which is safe as shipped because Docker's own network
namespace isolates it; the host-side `127.0.0.1:` prefix is the actual
guardrail.

If you change that line to `"8765:8765"` (dropping the `127.0.0.1:`
prefix) — for example, to put KingSec behind a reverse proxy or reach it
from another machine — the API becomes reachable from your network the
moment the container starts. Before doing that:
- Confirm `GET /api/v1/health` reports `"bootstrap_required": false`.
  While it's `true`, no administrator exists yet, and self-registration
  is disabled by default — see "First-Run Setup" below for how to fix
  that safely, before anyone else on the network can reach it.
- Put a reverse proxy with TLS in front of it; KingSec itself does not
  terminate TLS.
- Only then change the port mapping.

---

## Direct (non-Docker) Installation

Use this method for development, air-gapped environments, or when Docker
is not available. **KingSec is not published on PyPI** — `pip install
kingsec` will fail. Install from a repository checkout instead.

### Automated setup (recommended for a first install)

From the repository root:
```bash
./kingsec-setup.sh            # or: ./kingsec-setup.sh --dev   (editable install + dev tooling)
```
This creates `.venv`, installs KingSec, applies the known binary-wheel
fixes (cffi / pydantic-core — the "missing compiled binary" class of
failures), generates secrets into `.env` (values are never printed),
runs the database migrations, and bootstraps the first admin account
(prompts for the credentials securely; skips if an admin already
exists). It is idempotent — safe to re-run after pulling updates.

Then start the backend with:
```bash
./kingsec-start.sh
```
(On Windows, run both scripts from Git Bash.) The manual steps below do
the same thing piece by piece — follow them instead if you need full
control over each stage.

### Manual steps

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

> **Note:** there is no `kingsec db init` command. The real CLI has
> exactly three entry points: `kingsec` (starts the server),
> `kingsec-migrate` (runs Alembic migrations), and `kingsec-bootstrap`
> (creates a recovery admin account — see "Recovering Admin Access"
> below). Host/port come from `KINGSEC_SERVER__HOST` /
> `KINGSEC_SERVER__PORT` and can also be overridden per-run with
> `kingsec --host` / `kingsec --port` — the flags are routed through the
> same validated environment variables, never a separate unvalidated
> path.

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

You usually don't need to fix this: KingSec now defaults to **HTML
reports on Windows** (`KINGSEC_REPORTING__REPORT_FORMAT` defaults to
`html` there, `pdf` everywhere else), so report generation works out of
the box with zero native dependencies — the startup log says so when
the default kicks in. Only set
`KINGSEC_REPORTING__REPORT_FORMAT=pdf` explicitly after installing the
GTK3 runtime below.

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

### Nikto: Windows Defender Quarantine

**Known environment issue, reproduced in this project's own testing:**
Nikto ships as a Perl script, and downloading it on Windows has been
observed to trigger Windows Defender (or another antivirus product) to
quarantine the file before it can run — `nikto` then reports as not
installed (`kingsec doctor` will show it as `NOT FOUND` even after you've
downloaded it) with no further explanation from KingSec itself, since
KingSec only ever sees "the binary isn't on `PATH`," not why.

If `kingsec doctor` reports nikto missing right after installing it:
1. Check Windows Security → Virus & threat protection → Protection
   history for a recent quarantine action naming the nikto files.
2. Restore the quarantined file(s), or add an exclusion for nikto's
   install directory, then re-run `kingsec doctor` to confirm it now
   detects the binary.
3. If your organization's antivirus policy won't allow an exclusion,
   consider running nikto inside the Docker path instead (a Linux
   container is not subject to this specific Windows Defender behavior).

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
| `KINGSEC_JWT__SECRET_KEY` | **Effectively always required** | Has an insecure built-in default (the placeholder string), but the server rejects both that placeholder and an empty value at startup in every environment, not just production. A short non-empty value is still accepted outside production. |
| `KINGSEC_SECRETS__API_KEY_PEPPER` | **Effectively always required** | Same rejection rule as above — the placeholder (`CHANGE-ME-IN-PRODUCTION-DO-NOT-USE-DEFAULT`) and an empty value are both rejected in every environment. |
| `KINGSEC_SERVER__HOST` | Optional | Defaults to `127.0.0.1` (loopback-only). |
| `KINGSEC_SERVER__PORT` | Optional | Defaults to `8765`. |
| `KINGSEC_SERVER__ALLOW_EXTERNAL_BIND` | Optional | Must be `true` to bind to `0.0.0.0`; otherwise the server raises a startup error rather than silently exposing itself. |
| `KINGSEC_STORAGE__DATA_DIR` | Optional | Defaults to `~/.kingsec` (SQLite). Used by **both** migrations and the running server. |
| `KINGSEC_STORAGE__DATABASE_URL` | **Migration-only — do not set expecting it to affect the server** | Read only by the Alembic CLI (`env.py`, direct `os.environ` access), not by `Settings`. Setting it makes the running server (`kingsec` / `python -m kingsec`) refuse to start with `ConfigError: ... Extra inputs are not permitted`. |
| `ALEMBIC_DATABASE_URL` | Optional, migration-only | Highest-precedence override for `kingsec-migrate` specifically. When unset, migrations fall back to `KINGSEC_STORAGE__DATABASE_URL` if set, otherwise the same SQLite file the server uses. |
| `KINGSEC_REPORTING__REPORT_FORMAT` | Optional | `pdf` or `html`. Report deliverable format. Defaults to `pdf`, except on Windows where it defaults to `html` (WeasyPrint's GTK3 system libraries can't come from pip, so PDFs fail there until the GTK3 runtime is installed separately — see "Windows-Specific Notes"). |

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
of the 6 wired scanners are mandatory: KingSec starts and runs fine with zero
scanners installed, it just skips any assessment that requires one that
is missing.

**Note:** After installing a scanner, restart KingSec so scanner
discovery re-detects it. Run `kingsec doctor` at any point to see
exactly which scanners are usable and the exact fix for any that
aren't — it is the fastest way to check the steps below actually
worked. `doctor` verifies this by actually invoking each scanner's own
version-probe command (harmless — the same `--version` an operator would
run by hand), not just checking that a binary is present on PATH; a
binary that's present but fails to execute is reported NOT usable, with
a reason naming the execution failure, never silently as `[OK]`.

### Step: Nuclei templates

Nuclei needs its template database before it can find anything. Run
nuclei's own update command once after installing it (and periodically
afterward — new templates ship continuously):
```
nuclei -update-templates
```

Measured against the real command on a real Windows host (Phase 2B Task
6): **~86 MB on disk, ~13,900 template files, ~6 minutes** wall clock —
not the ~728 MB sometimes assumed from a rough git-clone size estimate.
The templates land in **nuclei's own per-user global directory**
(`~/nuclei-templates` — on Windows, `%USERPROFILE%\nuclei-templates`),
independent of `KINGSEC_STORAGE__DATA_DIR` and outside both KingSec's data
directory and its own `~/.kingsec` convention. Relevant for a future
Docker image: this path needs its own volume (or an explicit nuclei
config override to relocate it into the data volume) if templates should
persist across container recreation the same way KingSec's own data does.

### Step: A wordlist for FFUF and Gobuster

FFUF and Gobuster both need a `-w <wordlist>` to fuzz with — there is no
default bundled with KingSec (a wordlist is a real, required asset, and
KingSec does not choose one on your behalf; see
`docs/audits/KINGSEC-TASK3B-ASSET-PROVISIONING-PROPOSAL.txt` for why).
The recommended file is SecLists' `Discovery/Web-Content/common.txt` — a
small, focused list of common web paths/filenames (not the full ~3.6 GB
SecLists collection), MIT-licensed. KingSec's conventional location for
it is `~/.kingsec/wordlists/common.txt`, matching the same `~/.kingsec`
home directory KingSec's own data storage already uses
(`KINGSEC_STORAGE__DATA_DIR`'s default).

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.kingsec\wordlists" | Out-Null
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -OutFile "$env:USERPROFILE\.kingsec\wordlists\common.txt"
$env:KINGSEC_FFUF__WORDLIST = "$env:USERPROFILE\.kingsec\wordlists\common.txt"
$env:KINGSEC_GOBUSTER__WORDLIST = "$env:USERPROFILE\.kingsec\wordlists\common.txt"
```

**Linux / macOS (bash):**
```bash
mkdir -p ~/.kingsec/wordlists
curl -sSL -o ~/.kingsec/wordlists/common.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
export KINGSEC_FFUF__WORDLIST=~/.kingsec/wordlists/common.txt
export KINGSEC_GOBUSTER__WORDLIST=~/.kingsec/wordlists/common.txt
```

`kingsec doctor` prints this exact command (in the form matching the
platform it's actually running on) as the `fix:` line for ffuf/gobuster
whenever the wordlist is missing — it never has to be looked up
separately. The `export`/`$env:` forms above only last for the current
shell session; add the variable to your `.env` file (or a permanent
shell profile / System Environment Variable) to make it stick across
restarts.

### Step: ZAP on Windows — the official installer, not Chocolatey

On Windows, the Chocolatey `zap` package installs a `.bat` shim on PATH
(a re-router to a nested `.bat` chain), **not** a real executable. KingSec
invokes scanners as an argument list with `shell=False` — the essential
defence against command injection via a scan target — and Windows'
process-creation API (`CreateProcess`, what `shell=False` uses) cannot
launch a `.bat`/`.cmd` file directly the way a shell can. This is a
Windows OS limitation, not a KingSec bug, and it cannot be worked around
without reintroducing a shell (which command injection requires KingSec
to never do). The failure is not a clean "not found" either — Windows'
implicit `cmd.exe` fallback for a `.bat` target can itself fail with
"The input line is too long.", which is why `kingsec doctor` verifies
actual execution (see the Note above), not just that a binary is present
on PATH.

Install ZAP via the **official installer** (not Chocolatey), then point
`KINGSEC_ZAP__BINARY_PATH` at the real `ZAP.exe` it installs — a genuine
install4j-generated native launcher, not a script:

**Windows (PowerShell):**
```powershell
$env:KINGSEC_ZAP__BINARY_PATH = "C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe"
```

As with the wordlist variable above, this only lasts for the current
shell session; add it to your `.env` file (or a permanent shell profile /
System Environment Variable) to make it stick across restarts. Linux/macOS
installs (the official Docker image or the `zaproxy` package) are
unaffected — this is a Windows-only `.bat`-resolution issue.

`kingsec doctor` prints this same command as the `fix:` line for zap on
Windows whenever it's not usable.

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

`kingsec-bootstrap` is also how you recover if every admin account is
lost. Same command as "First-Run Setup" below:
```bash
kingsec-bootstrap --username <name> --password <secret>
```
This refuses to run if an admin already exists, and refuses to run if
migrations have not been applied. (Deliberately: it checks for an
existing *admin*, not any user at all — if it required no users to exist
whatsoever, it would refuse in exactly the recovery scenario it exists
for, whenever ordinary accounts survive an admin's loss.)

---

## First-Run Setup

### Step 1: Access the API

Open `http://127.0.0.1:8765/docs` for interactive Swagger UI, or run the
frontend (see "Running the Frontend" above) and open
`http://localhost:5173` for the browser UI.

### Step 2: Create the First Admin Account

Self-registration is disabled by default, and the UI's "Register" link
will not create an admin even when enabled — self-registered accounts
are always Viewer, never Admin. The **only** way to create the first
administrator is `kingsec-bootstrap`, run once against your installed
instance:
```bash
kingsec-bootstrap --username admin --password "<a strong password>"
```
This requires migrations to already be applied (see "Database
Migrations" above) and refuses to run if an admin already exists. Log in
with these credentials at `http://127.0.0.1:8765/docs` or the frontend.

If you want ordinary users to be able to sign themselves up afterward
(as Viewers — never Admin), set
`KINGSEC_SECURITY__ALLOW_SELF_REGISTRATION=true`. It is off by default:
on a network-reachable instance, an open signup endpoint is worth
enabling deliberately, not by accident.

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
