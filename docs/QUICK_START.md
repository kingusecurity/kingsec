# KingSec Quick Start

This guide gets the KingSec application running, creates the first
administrator, and walks through an authorization-gated assessment. KingSec
only scans systems you are authorized to assess.

## Verification boundary

- **INFERRED (2026-10-07):** the commands, paths, configuration keys, UI
  location, bootstrap flow, profile identifiers, and authorization flow below
  match the current repository source.
- **NOT TESTED (2026-10-07):** this working tree has not yet completed a fresh
  Docker build, source install, browser walkthrough, or live scanner run.
- **NOT TESTED:** the current native Windows installer has not been exercised
  on a Windows host.
- **MISSING from the base Docker image:** external scanner executables. The
  image contains the KingSec API, bundled browser UI, migrations, and report
  runtime, but it does not install Nmap, Nuclei, Nikto, FFUF, Gobuster, OWASP
  ZAP, Semgrep, Trivy, or Amass.

Historical test evidence elsewhere in this repository does not establish that
the current uncommitted working tree passes those same checks.

## Choose an installation path

Use Docker to evaluate the application and its UI in an isolated runtime. To
run an actual assessment, add the required scanner executables to a derived
image; programs installed only on the Docker host are not visible inside the
container.

Use the source installer when compatible scanners are already installed on the
same computer and available on `PATH`. For a first host assessment, Nmap is the
only scanner required by the `quick-scan` profile.

## Option A: Docker

### 1. Configure the three required secrets

From the repository root:

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Put the three generated values into `.env`, in order:

```dotenv
KINGSEC_JWT__SECRET_KEY=<first-value>
KINGSEC_SECRETS__API_KEY_PEPPER=<second-value>
KINGSEC_SECRETS__ENCRYPTION_KEY=<third-value>
```

Do not commit `.env` or reuse these values in another environment.

### 2. Build and start the application

```bash
docker compose up -d --build
docker compose ps
curl http://127.0.0.1:8765/api/v1/health
```

The container runs database migrations before starting KingSec. The browser UI
is bundled into the same artifact and is served at
`http://127.0.0.1:8765/`; Swagger UI is at
`http://127.0.0.1:8765/docs`.

A fresh instance should report `"bootstrap_required": true` until the next
step is complete. If startup fails, inspect it with:

```bash
docker compose logs kingsec
```

### 3. Create the first administrator

Self-registration creates a Viewer; it never creates the first administrator.
Use the dedicated bootstrap command instead:

```bash
docker compose exec kingsec kingsec-bootstrap \
  --username admin \
  --email admin@example.com
```

Enter the password at the interactive prompt so it does not appear in shell
history or the process list. The command refuses to create another account
when an administrator already exists.

Confirm that bootstrap is complete:

```bash
curl http://127.0.0.1:8765/api/v1/health
```

The response should now contain `"bootstrap_required": false`. Open
`http://127.0.0.1:8765/` and log in with the administrator account.

### 4. Supply scanners before assessing a target

Open **Live Monitoring** and review **Scanner Health**. A scanner must be
installed inside the container, not just on the host. Build a derived image
with only the scanners and supporting assets you intend to use; see
[SCANNER_GUIDE.md](SCANNER_GUIDE.md) for per-scanner requirements.

Do not treat a started application as a scanner-ready installation. The
execution plan blocks a profile when one of its required scanners or assets is
unavailable, and reports unavailable optional scanners as coverage gaps.

## Option B: source installation

The source installers create a repository-local virtual environment, build and
bundle the browser UI, generate a private `.env`, apply migrations, check
scanner availability, and offer to bootstrap the first administrator.

Prerequisites are Python 3.11–3.13 and Node.js 20 or newer. Install each
external scanner separately and make it available on `PATH` before launching
KingSec.

Linux or macOS:

```bash
./scripts/install.sh
./data/start.sh
```

Windows PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
& "$env:LOCALAPPDATA\KingSec\start.cmd"
```

The scripts print the actual launcher path if you choose a non-default data
directory. The Windows installer defaults report output to HTML because native
PDF generation requires the GTK runtime. See [INSTALL.md](INSTALL.md) for the
manual installation path and platform-specific details.

## Run the first authorized assessment

The steps below assume Nmap is reported usable and use loopback as the target.
Only proceed when the system running KingSec is yours to test.

### 1. Record authorization

Log in as an administrator, open **Authorization Grants**, and create an active
grant with:

- specification type: `ip_address`
- specification value: `127.0.0.1`
- the real authorizing person or ticket reference
- the real authorizing organization
- a validity window that includes the planned assessment

Grant creation and revocation are Admin-only. Analysts can view grants and use
the assessment form's read-only coverage check, but they cannot authorize their
own work.

For `domain`, `source_path`, and `container_image` targets, create the
corresponding exact grant type. Domain enumeration deliberately requires a
`domain` grant; a hostname or wildcard-hostname grant is not a substitute.

### 2. Create the assessment

Open **Assessments**, choose **New Assessment**, then enter:

- profile: **Quick Host Scan** (`quick-scan`)
- target type: **IP address** (`ip_address`)
- target: `127.0.0.1`
- the real `authorized_by` and scope/audit-trail values

Review both the execution plan and authorization coverage result. Resolve any
blocking scanner, asset, target, or grant message before submitting.

Creating an assessment saves it; it does not start scanning. Open the saved
assessment and use **Start Assessment** as a separate deliberate action.

### 3. Review coverage and results

Inspect every per-scanner outcome when the run reaches a terminal state:

- `completed` means every planned scanner succeeded.
- `completed_with_gaps` means at least one scanner was skipped, failed, or
  timed out; it is not full coverage.
- `failed` means the assessment did not produce a successful scanner run.

Review findings and their evidence before relying on them. A zero-finding run
is not proof that the target is secure; it only describes the successful
scanner coverage shown for that run.

Generate an HTML or PDF report only after reviewing the coverage disclosure.
Docker includes the libraries needed for PDF output. The native Windows source
path defaults to HTML unless GTK is installed.

## API users

The same flow is available through Swagger UI at
`http://127.0.0.1:8765/docs`:

1. `POST /api/v1/auth/login`
2. `POST /api/v1/authorization-grants`
3. `GET /api/v1/authorization-grants/check`
4. `POST /api/v1/assessments` with an explicit `profile_id`
5. `POST /api/v1/assessments/{assessment_id}/start`
6. `GET /api/v1/assessments/{assessment_id}`
7. `POST /api/v1/assessments/{assessment_id}/report`
8. `GET /api/v1/reports/{assessment_id}/download`

The API rejects unknown profiles, incompatible target/profile combinations,
and uncovered scan surfaces. Use the generated OpenAPI schema for the current
request fields instead of copying old assessment payloads.

## Common first-run problems

| Symptom | Action |
|---|---|
| `bootstrap_required` remains `true` | Run `kingsec-bootstrap` in the same environment and against the same data directory as the server. |
| Container exits during startup | Check `docker compose logs kingsec`; confirm all three required secrets are set in `.env`. |
| Required scanner is unavailable | Install it in the same runtime as KingSec and configure any required templates, wordlist, or database. |
| Scanner exists on the Docker host but is missing in KingSec | Add it to a derived KingSec image; host executables are not inherited by a container. |
| Authorization coverage is incomplete | Create the correct active grant as an Admin; do not use the override as a routine workflow. |
| Assessment is `completed_with_gaps` | Read every scanner outcome and the report coverage disclosure before interpreting the findings. |
| Native Windows PDF generation fails | Use HTML output or install the documented GTK runtime. |

## Next documentation

- [INSTALL.md](INSTALL.md) — complete deployment and configuration reference
- [SCANNER_GUIDE.md](SCANNER_GUIDE.md) — scanner binaries, assets, and discovery
- [USER_GUIDE.md](USER_GUIDE.md) — assessment and findings workflow
- [ADMIN_GUIDE.md](ADMIN_GUIDE.md) — users, roles, backups, and hardening
- [API_REFERENCE.md](API_REFERENCE.md) — REST API reference
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — detailed failure diagnosis
