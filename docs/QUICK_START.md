# KingSec v2.0.0 Quick Start Guide

Zero to first assessment in under 15 minutes.

Author: Abdul Mannan
Contact: kingusecurity@gmail.com
GitHub: https://github.com/kingusecurity/kingsec

---

## Before You Start

KingSec is two separate pieces you run independently:

1. **Backend** (REST API) — this guide gets it running via Docker.
2. **Frontend** (browser UI) — a separate app you run with `npm run dev`.
   There is no bundled Docker image with the UI included yet.

If you'd rather skip the browser UI and drive everything via the API
directly (curl or the Swagger UI at `/docs`), you can stop after Step 2.

---

## Prerequisites

- Docker 24.0+ installed and running
- Node.js 20+ and npm 10+ (only if you want the browser UI)
- A modern web browser
- At least 4 GB of available RAM

---

## Step 1: Build and Start the Backend

There is no published Docker image — build it locally from this
repository.

```bash
docker build -t kingsec:2.0.0 .
```

Generate the one environment variable that is **always** required (the
server will not start without it, in any environment):

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Copy the output, then start the container:

```bash
docker run -d \
  --name kingsec \
  --restart unless-stopped \
  -p 127.0.0.1:8765:8765 \
  -e KINGSEC_SECRETS__ENCRYPTION_KEY="<paste-the-key-you-generated>" \
  -v kingsec-data:/home/kingsec/.kingsec \
  kingsec:2.0.0
```

Confirm it's running:

```bash
docker ps --filter name=kingsec
curl http://127.0.0.1:8765/api/v1/health
```

Expected health response: `{"status":"ok"}`. If the container exited
instead, run `docker logs kingsec` — a `ConfigError` naming a missing
environment variable is the most common first-run issue, and it's
self-explanatory (it tells you exactly which variable to set).

You can explore the API interactively right now at
**http://127.0.0.1:8765/docs** (Swagger UI) without doing anything else —
every endpoint below can be called from there instead of curl or the
browser UI.

---

## Step 2: Register the First Admin Account

The first user ever registered on a fresh install is automatically
granted the **Admin** role — verified in this audit end-to-end (register
→ the very first account really does come back with `"role":"Admin"`).

Via curl:
```bash
curl -X POST http://127.0.0.1:8765/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","email":"admin@example.com","password":"Choose-A-Strong-Password-1!"}'
```
Password requirement (verified against the actual validation code, not
assumed): 8–128 characters, containing at least one uppercase letter, one
lowercase letter, and one digit. No special character is required.

Then log in to get a bearer token for the remaining steps:
```bash
curl -X POST http://127.0.0.1:8765/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Choose-A-Strong-Password-1!"}'
```
Copy the `access_token` from the response — you'll pass it as
`-H "Authorization: Bearer <token>"` on every request below (or, if using
Swagger UI, click "Authorize" and paste it there).

**If you're running the browser UI instead:** see "Running the Browser
UI" below first, then register/log in through the Login/Register screens
there — same underlying API calls, just through a form.

---

## Step 3: Create and Run Your First Assessment

```bash
TOKEN="<your access_token>"

curl -X POST http://127.0.0.1:8765/api/v1/assessments \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"target_value":"127.0.0.1","target_type":"ip_address","authorized_by":"admin","scope":"127.0.0.1"}'
```
Copy the `assessment_id` from the response, then start it:
```bash
curl -X POST http://127.0.0.1:8765/api/v1/assessments/<assessment_id>/start \
  -H "Authorization: Bearer $TOKEN"
```
Poll its status until it's `completed`:
```bash
curl http://127.0.0.1:8765/api/v1/assessments/<assessment_id> \
  -H "Authorization: Bearer $TOKEN"
```

**Verified in this audit:** scanning `127.0.0.1` with the default
profile (Nmap) on a machine with no scanners specially configured
completed in under 15 seconds and returned real findings. Scanning a
hostname target instead of an IP address will generally take longer.

If you'd rather use a real external target, only scan systems you are
authorized to test — `authorized_by` and `scope` exist specifically to
record that authorization.

---

## Step 4: View Findings and Generate a Report

Findings are included in the assessment detail response from Step 3
(`GET /api/v1/assessments/<id>`), or via `GET /api/v1/findings` for the
searchable/filterable list across all your assessments.

Generate a report:
```bash
curl -X POST http://127.0.0.1:8765/api/v1/assessments/<assessment_id>/report \
  -H "Authorization: Bearer $TOKEN"
```

> **Windows / Linux / macOS direct installs only (not Docker):** if this
> returns a `500` error with code `KS-REPORT-001`, your machine is
> missing WeasyPrint's native GTK libraries, which `pip install` does not
> provide. This is a real, confirmed installation gap on non-Docker
> installs — see `INSTALL.md`'s "PDF Report Generation Requires GTK3"
> section for the fix. The Docker image already includes these libraries
> and is not affected.

Download it:
```bash
curl -O -J http://127.0.0.1:8765/api/v1/reports/<assessment_id>/download \
  -H "Authorization: Bearer $TOKEN"
```

---

## Running the Browser UI

The web UI is a separate app and is not served by the backend container
above.

```bash
cd frontend
npm install
npm run dev
```
Open **http://localhost:5173**. The dev server automatically proxies API
calls to `http://127.0.0.1:8765` — the backend from Step 1 must already
be running. Log in or register from the UI exactly as in Step 2.

Once logged in:
1. Sidebar → **Assessments** → **New Assessment**.
2. Choose a target and target type, review the generated execution plan
   (it shows which scanners will run based on what's installed), then
   launch it.
3. The assessment detail page auto-refreshes every few seconds while
   running, showing live per-scanner progress.
4. When complete, open the **Findings** tab, then **Generate Report**
   from the assessment detail page and download it from there or from
   the **Reports** page in the sidebar.

---

## Quick Reference

| Task | Command / URL |
|---|---|
| Start (Docker) | `docker start kingsec` |
| Stop (Docker) | `docker stop kingsec` |
| View logs (Docker) | `docker logs kingsec -f` |
| REST API | `http://127.0.0.1:8765/api/v1` |
| Swagger UI | `http://127.0.0.1:8765/docs` |
| Browser UI (run separately, see above) | `http://localhost:5173` |
| Health check | `curl http://127.0.0.1:8765/api/v1/health` |
| Default port | `8765` |
| Data directory (Docker) | named volume `kingsec-data` → `/home/kingsec/.kingsec` |
| Data directory (direct install) | `~/.kingsec` by default |

---

## Next Steps

- Read `USER_GUIDE.md` for detailed feature walkthroughs.
- Read `ADMIN_GUIDE.md` for user/role management and backups.
- Read `SCANNER_GUIDE.md` to install more scanners beyond whatever your
  machine already has (Nmap is the only one likely present by default).
- Read `INSTALL.md` for the full installation reference, including every
  environment variable and its verified real-world behavior.

---

## Getting Help

- Full documentation: `INSTALL.md`, `USER_GUIDE.md`, `ADMIN_GUIDE.md`,
  `TROUBLESHOOTING.md`
- GitHub Issues: https://github.com/kingusecurity/kingsec/issues
- Email support: kingusecurity@gmail.com
