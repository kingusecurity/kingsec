# KingSec v2.0.0 Installation Guide

Author: Abdul Mannan
Contact: kingusecurity@gmail.com
GitHub: https://github.com/kingusecurity/kingsec

---

## Important: what this guide covers

KingSec contains two build components that ship as one application artifact:

1. **The backend** — a FastAPI REST API backed by local SQLite storage. This
   is what `docker run`, `kingsec-migrate`, and `kingsec` set up and start.
   It exposes the API and an interactive Swagger UI at `/docs`.
2. **The frontend** — a React SPA in `frontend/`. Docker and the one-shot
   source installers build it and bundle it into the Python package; the
   backend then serves it at `/`. `npm run dev` is only the development
   workflow, where Vite proxies API calls to the backend.

The supported production paths below prepare both pieces. Advanced API-only
operators may build a wheel without the generated static directory, in which
case the API and `/docs` still work but `/` has no SPA.

---

## System Requirements

### Required toolchain

- Source install: CPython 3.11, 3.12, or 3.13; Node.js 20 or newer; npm.
- Docker install: a current Docker Engine or Docker Desktop; Docker Compose v2
  for the Compose path.
- Scanner binaries and their assets are separate dependencies. Install only the
  scanners needed by the profiles you intend to operate.

CPU, memory, disk, and scan duration depend heavily on target size, selected
scanners, and scanner concurrency. This release has no benchmark-backed minimum
hardware claim; provision conservatively and monitor the host during a customer
walkthrough before choosing production capacity.

### Supported Operating Systems

The Bash installer targets Linux and macOS. The PowerShell installer targets
Windows 10/11. The container path works anywhere supported by Docker's Linux
container engine.

**Windows verification boundary:** Docker Desktop's Linux-container path has
been exercised previously. The native PowerShell installer is designed for
Windows 10/11 and forces binary wheels for `cffi` and `pydantic-core`, but its
current revision must still be validated on a real Windows host before a
native-Windows clean-install claim is made.

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
The build uses `git archive HEAD` so the image contains committed source only.
Build from a Git checkout with `.git` present, and commit the exact revision you
intend to package before building.
This is a multi-stage build (Python 3.12-slim base, builds a wheel, then
installs it into a slim runtime image as a non-root user). It takes a few
minutes on first build.

### Step 3: Configure Required Secrets

```bash
cp .env.example .env
```
Open `.env` and set all three required secrets:

- `KINGSEC_JWT__SECRET_KEY`
- `KINGSEC_SECRETS__API_KEY_PEPPER`
- `KINGSEC_SECRETS__ENCRYPTION_KEY`

Generate suitable values with:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"  # JWT secret
python -c "import secrets; print(secrets.token_urlsafe(48))"  # API-key pepper
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"  # encryption key
```
### Step 4: Run the Container

```bash
docker run -d \
  --name kingsec \
  --restart unless-stopped \
  --env-file .env \
  -e KINGSEC_SERVER__HOST=0.0.0.0 \
  -e KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true \
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
  -e KINGSEC_SERVER__HOST=0.0.0.0 `
  -e KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true `
  -p 127.0.0.1:8765:8765 `
  -v kingsec-data:/home/kingsec/.kingsec `
  kingsec:2.0.0
```

Notes on the exact flags used above:
- The named volume `kingsec-data` mounts to `/home/kingsec/.kingsec` —
  this is the container's real data directory (there is no `/app/data`).
- Binding to `127.0.0.1` on the host keeps the API off your network by
  default even though the container itself listens on `0.0.0.0` inside
  its own isolated network namespace.
- `KINGSEC_SERVER__ALLOW_EXTERNAL_BIND=true` is the required explicit opt-in
  for the container's internal wildcard bind. It does not change the safe
  loopback-only host publication above.

### Step 5: Verify the Container is Running

```bash
docker ps --filter name=kingsec
docker logs kingsec --tail 50
curl http://127.0.0.1:8765/api/v1/health
```
Before bootstrapping an administrator, the health response is
`{"status":"ok","bootstrap_required":true}`. After bootstrap, the boolean is
`false`.

If the container exits immediately, `docker logs kingsec` will show a
`ConfigError` naming the missing environment variable — this is almost
always `KINGSEC_SECRETS__ENCRYPTION_KEY` not being set.

---

## Docker Compose Installation

The repository already includes a working `docker-compose.yml`. You do
not need to write your own.

```bash
cp .env.example .env
# Edit .env: set all three required secret values listed above.
docker compose up -d --build
docker compose logs -f      # follow logs
docker compose ps           # check status
docker compose down         # stop
```

The bundled compose file builds the image from the committed source tree using
the local `Dockerfile`,
binds the API to `127.0.0.1:8765`, and stores data in a named volume —
you do not need to create one yourself.

The base image bundles the UI and KingSec application, but not the nine external
scanner executables. Scanner binaries installed on the Docker host are not
automatically visible inside the container. For scanner-backed assessments,
extend the image with the specific scanners and assets you are licensed and
authorized to use, then verify the resulting image with
`docker exec kingsec kingsec doctor`. Source installation is the simpler path
when scanners already exist on the host.

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

### Step 1: Clone the Repository

```bash
git clone https://github.com/kingusecurity/kingsec.git
cd kingsec
```

### Recommended: one-shot installers

The scripts build the SPA, create `.venv`, install from the checkout, generate
an access-restricted root `.env` with all three secrets and an absolute data
directory, validate the cryptographic configuration, run migrations without
hiding failures, run the read-only `kingsec doctor` scanner preflight, and
create a launcher that always uses the checkout virtual environment and working
directory. Before migrating an existing SQLite database, the scripts create a
consistent snapshot under the selected data directory's `backups/` folder.

Existing `.env` files are preserved and must already contain valid
configuration. The installer and its launcher deliberately pass the selected
data directory as an explicit runtime override (`KINGSEC_DATA_DIR` on Bash or
`-InstallDir` on PowerShell). They also ignore the migration-only
`ALEMBIC_DATABASE_URL` and `KINGSEC_STORAGE__DATABASE_URL` variables so Alembic
cannot be redirected to a database the server will not use. Stop a running
KingSec process before rerunning an installer for an upgrade.

Linux/macOS:

```bash
./scripts/install.sh
```

Windows PowerShell (also usable when the checkout was opened from Git Bash):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

The default launchers are `./data/start.sh` on Linux/macOS and
`$env:LOCALAPPDATA\KingSec\start.ps1` on Windows. Each installer prints the
resolved path; use that printed path when you selected a custom data directory.

The Windows installer defaults reports to HTML so a fresh machine works
without GTK3. The Bash installer performs an in-memory PDF render preflight and
chooses PDF only when the native libraries work; otherwise it also defaults to
HTML. Install the native dependencies and change
`KINGSEC_REPORTING__REPORT_FORMAT=pdf` when PDF output is required.

### Manual installation

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows (PowerShell):
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Build the UI and install KingSec:

```bash
cd frontend
npm ci
npm run build
cd ..
rm -rf src/kingsec/adapters/inbound/web/static
mkdir -p src/kingsec/adapters/inbound/web/static
cp -R frontend/dist/. src/kingsec/adapters/inbound/web/static/
python -m pip install --only-binary=cffi,pydantic-core .
```

On Windows PowerShell, replace the three copy commands with:

```powershell
Remove-Item -Recurse -Force src\kingsec\adapters\inbound\web\static -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force src\kingsec\adapters\inbound\web\static | Out-Null
Copy-Item -Recurse -Force frontend\dist\* src\kingsec\adapters\inbound\web\static\
```

This builds and installs the `kingsec` wheel and its runtime dependencies
(FastAPI, SQLAlchemy, Alembic, WeasyPrint, etc.) and creates three console
scripts in the venv: `kingsec`, `kingsec-migrate`, `kingsec-bootstrap`.

For development (linting, type-checking, tests) install the extra dev
tooling instead:
```bash
pip install -e ".[dev]"
```

Configure all three required secrets in the repository-root `.env`:

```bash
cp .env.example .env
```
KingSec auto-loads `.env` from the process working directory. Run migration,
bootstrap, and server commands from the repository root; do not `source` the
file. The one-shot launchers enforce the correct working directory.

> **Note:** there is no `kingsec db init` subcommand. The real CLI has
> three entry points: `kingsec`
> (starts the server), `kingsec-migrate` (runs Alembic migrations), and
> `kingsec-bootstrap` (creates a recovery admin account — see
> "Recovering Admin Access" below). `kingsec --host` and `kingsec --port`
> are supported overrides; environment variables remain the persistent form.

### Step 5: Initialize the Database

For a fresh database, run:

```bash
kingsec-migrate
```
This applies every Alembic migration to the SQLite database at
`KINGSEC_STORAGE__DATA_DIR/kingsec.db` (default: `~/.kingsec/kingsec.db`).
For an existing database, stop KingSec and create a SQLite-consistent backup
before running the command; see "Database Migrations" below. The one-shot
installers perform that snapshot automatically.

### Step 6: Start KingSec

```bash
kingsec
```
The service runs in the foreground, logging to stdout. Stop it with
Ctrl+C. For a background/production run, use a process manager (systemd,
supervisord, NSSM on Windows) — see below.

The browser UI is now at `http://127.0.0.1:8765/`, the API is at
`http://127.0.0.1:8765/api/v1`, and interactive Swagger docs are at
`http://127.0.0.1:8765/docs` when the frontend was bundled by Docker or the
one-shot installer.

### systemd Service File (Linux)

Create `/etc/systemd/system/kingsec.service`:
```ini
[Unit]
Description=KingSec Security Assessment Platform
After=network.target

[Service]
Type=simple
User=kingsec
WorkingDirectory=/opt/kingsec
Environment="PATH=/opt/kingsec/.venv/bin"
Environment="KINGSEC_SECRETS__ENCRYPTION_KEY=<your-generated-key>"
Environment="KINGSEC_JWT__SECRET_KEY=<your-production-secret>"
Environment="KINGSEC_SECRETS__API_KEY_PEPPER=<your-production-pepper>"
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

## Frontend Development

Production Docker/source installs bundle the React app and `kingsec` serves it
at `/`. Run Vite separately only while developing the frontend.

### Development

```bash
cd frontend
npm ci
npm run dev
```
Open **http://localhost:5173**. The Vite dev server proxies every `/api`
request to `http://127.0.0.1:8765` (hardcoded in `frontend/vite.config.ts`
— there is no environment variable to change this; edit the file
directly if you need a different backend port). The backend must already
be running for the proxy to work.

### Manual production bundle

```bash
cd frontend
npm ci
npm run build
```
This produces `frontend/dist/`. Copy its contents into
`src/kingsec/adapters/inbound/web/static/` **before** building/installing the
Python wheel; Hatch includes that generated directory and the backend serves
the SPA with fallback routing. The one-shot installers and Dockerfile perform
these steps automatically.

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

### Report formats and GTK3

PDF generation uses WeasyPrint, which needs system-level GTK/Pango/Cairo
libraries that `pip install` does **not** provide on Windows. The Windows
installer therefore writes `KINGSEC_REPORTING__REPORT_FORMAT=html`; valid HTML
reports work without importing WeasyPrint. Selecting PDF without the native
runtime fails explicitly with `KS-REPORT-001`, rather than returning a corrupt
or mislabeled artifact.

Fix: download and run the GTK3 runtime installer from
https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases,
then restart your terminal (and KingSec) so the updated `PATH` takes
effect, set `KINGSEC_REPORTING__REPORT_FORMAT=pdf`, and restart KingSec. This
only affects direct/non-Docker installs — the Docker image already bundles the
required libraries.

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

Generate the two secret values with:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # KINGSEC_SECRETS__ENCRYPTION_KEY
python -c "import secrets; print(secrets.token_urlsafe(64))"                                # KINGSEC_JWT__SECRET_KEY / API_KEY_PEPPER
```

---

## Scanner Dependency Installation

KingSec uses pluggable scanners. Install them according to your
assessment needs — see the table in `README.md`'s "Scanner Environment"
section for the exact per-OS install commands and required assets. KingSec can
start with no scanners installed, but an assessment profile cannot proceed
when one of its required scanners or assets is unavailable. Missing optional
scanners are recorded as coverage gaps rather than successful zero-finding
runs.

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

For an existing SQLite installation:

1. Stop the KingSec server so no new writes begin during the upgrade.
2. Confirm the data directory printed by KingSec is the database you intend to
   change. Do not set `ALEMBIC_DATABASE_URL` or
   `KINGSEC_STORAGE__DATABASE_URL` for a normal SQLite deployment; those
   migration-only overrides can point Alembic somewhere the server never uses.
3. Create a consistent backup. The one-shot installers use Python's SQLite
   backup API and save it under `<data-dir>/backups/`. For a manual upgrade,
   use the application's Backup feature while it is running, then stop the
   server, or use the same SQLite backup API from an operator-controlled
   maintenance command.
4. Inspect the current revision and migration history, then apply the upgrade.

```bash
# Show current migration version
alembic current

# Show migration history
alembic history --verbose

# Apply all pending migrations
kingsec-migrate                       # pip install (uses the packaged alembic.ini)
alembic upgrade head                  # repo checkout — run from the repo root; the
                                      # root-level alembic.ini already points at
                                      # src/kingsec/alembic, no -c flag needed
```

**Startup validation:** the application checks that migrations have been
applied at startup and raises `RuntimeError` with clear instructions if
not. If you see this, run the command above before starting the server
again.

There is no `kingsec db backup/restore/rollback` command. A plain file copy is
acceptable only while the server is stopped and no process has the SQLite
database open. While the application is running, use its Backup feature
(`POST /api/v1/backups`) or SQLite's backup API instead of copying a live file.

---

## Recovering Admin Access

`kingsec-bootstrap` is also how you recover if every admin account is
lost. Run it in the same runtime and against the same data directory as the
server:

```bash
# Source install, from the repository root
kingsec-bootstrap --username <name>

# Docker Compose
docker compose exec kingsec kingsec-bootstrap --username <name>

# Container started with the raw docker run example above
docker exec -it kingsec kingsec-bootstrap --username <name>
```

The source-install command above assumes the virtual environment is active. If
you used a one-shot installer, its completion message prints the exact venv and
data-directory command to use.

This command refuses to run if an admin already exists, and refuses to run if
migrations have not been applied. (Deliberately: it checks for an existing
*admin*, not any user at all — if it required no users to exist whatsoever, it
would refuse in exactly the recovery scenario it exists for, whenever ordinary
accounts survive an admin's loss.)

## First-Run Setup

### Step 1: Create the First Admin Account

Self-registration is disabled by default, and the UI's "Register" link will
not create an admin even when enabled — self-registered accounts are always
Viewer, never Admin. Use the matching bootstrap command from "Recovering Admin
Access" above. For example, a source installation with its virtual environment
active uses:

```bash
kingsec-bootstrap --username admin
```
The command securely prompts for and confirms the password. `--password` is
still available for non-interactive automation, but can be visible in process
arguments and shell history and is not recommended for an interactive setup.
This requires migrations to already be applied (see "Database
Migrations" above) and refuses to run if an admin already exists. Log in
with these credentials at `http://127.0.0.1:8765/docs` or the frontend.

If you want ordinary users to be able to sign themselves up afterward
(as Viewers — never Admin), set
`KINGSEC_SECURITY__ALLOW_SELF_REGISTRATION=true`. It is off by default:
on a network-reachable instance, an open signup endpoint is worth
enabling deliberately, not by accident.

### Step 2: Start KingSec and Sign In

Start the service, then open `http://127.0.0.1:8765/` for the bundled browser
UI or `http://127.0.0.1:8765/docs` for interactive Swagger UI. The public
`GET /api/v1/health` response should now contain
`"bootstrap_required": false`.

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
One of the three required secrets is missing or invalid. See "Environment
Variables" above; the error names the exact setting.

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

### Web UI shows a 404 at port 8765
The installed wheel was built without the generated SPA. Re-run the one-shot
installer, use the Docker build, or follow "Manual production bundle" before
reinstalling the wheel. The API and `/docs` remain available independently.
