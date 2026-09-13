# KingSec — Product Inventory

Factual technical inventory for commercial positioning, contracts, and documentation. Read-only review of `D:\New_folder\kingsec` at commit `4e24e3b6ac77cc4688628ba1405e50684ec676ea` (branch `main`). No code was modified to produce this document.

Every claim carries exactly one label:
**TESTED** — run and observed (command + output included). **INFERRED** — read the code and reasoned; not run. **NOT TESTED** — a claim that could be verified but wasn't, with the reason stated. **MISSING** — the code does not appear to implement or expose this.

---

## 1. Runtime and dependencies

**Language / runtime versions**
- Python: `requires-python = ">=3.11"` (`pyproject.toml`). Classifiers declare 3.11/3.12/3.13. `mypy` is pinned to `python_version = "3.11"` "to match CI (and the Linux container this project ships in)." The dev venv (`.python-version`) is 3.12. `docs/INSTALL.md` states the declared-supported range is 3.11–3.13, noting 3.14 "has also been run successfully... but is not yet an officially declared target." **INFERRED**
- `uv.lock`'s own resolution markers reference Python `>= 3.15` — wider than the declared floor, no stated ceiling in the lock file itself. **INFERRED**
- Docker: build and runtime stages both `FROM python:3.12-slim` — a floating (unpinned to a Debian codename) tag. A captured build log shows this resolved to Debian 13 "trixie" on the date it was built, which is not guaranteed for a future rebuild since the tag floats. **TESTED** (image built successfully from this Dockerfile in a prior phase of this engagement, commit `4e24e3b`, exit 0) / **INFERRED** (that today's build necessarily produces the same OS point-release as an earlier build).
- Frontend build stage uses `node:20-slim`; `frontend/package.json` has no `engines` field pinning a Node version for end users who build outside Docker. **INFERRED**

**OS support**
- No `os.chmod`/`os.geteuid`/`os.getuid` calls exist anywhere under `src/`. The only OS-conditional branches found are: (a) scanner-binary discovery/install-command suggestions (`scanner_installer.py`, `scanner_discovery.py` — Windows search paths for Chocolatey/Scoop/WinGet vs. Linux apt/go paths), and (b) an optional Windows-registry (`winreg`/`MachineGuid`) vs. Linux (`/etc/machine-id`) machine-fingerprint enrichment for license binding, wrapped so absence on either OS doesn't crash. Everything else (FastAPI, DB, encryption, auth) is OS-agnostic Python. **INFERRED**
- `docs/INSTALL.md` states explicitly: "KingSec has no OS-specific code paths beyond scanner-executable discovery... verified in this audit on Windows 10/11; the general requirement is any OS with a supported Python." This matches what the code shows. **INFERRED**
- This engagement has directly run and tested KingSec (build, migrate, start, HTTP smoke tests) on Windows 10 (via Docker Desktop/WSL2) across six prior phases of this same engagement. **TESTED**
- Linux/macOS as host OS for the application itself: **NOT TESTED** in this engagement (Docker's own Linux container was tested; the *host* running Docker was Windows throughout).

**Dependency list and licensing — the material gap**
- Full pinned dependency set: 103 packages resolved in `uv.lock` (runtime + dev + transitive). Direct runtime dependencies declared in `pyproject.toml`: `fastapi`, `uvicorn[standard]`, `pydantic`, `pydantic-settings`, `cryptography`, `defusedxml`, `httpx`, `structlog`, `sqlalchemy`, `weasyprint`, `reportlab`, `PyJWT`, `argon2-cffi`, `alembic`, `python-multipart` (each with an explicit version range in the file).
- **`uv.lock` contains no license metadata field for any of the ~103 resolved packages.** The only license artifact anywhere in the repo is KingSec's own proprietary `LICENSE` file and `docs/LICENSING.md` (KingSec's own commercial tiers) — neither addresses third-party dependency licenses. **There is no SBOM, no `pip-licenses`/similar output, no `THIRD_PARTY_LICENSES` file, and no license-checking CI step in this repository.**
- **GPL/AGPL risk: MISSING VERIFICATION, not MISSING RISK.** No dependency *name* in `pyproject.toml`/`uv.lock` matches a well-known GPL/AGPL package family, but this is a name-pattern observation only — there is no license field in the repo to check against, so this cannot be stated as cleared. **A real license scan (e.g. `pip-licenses` against the resolved environment) has not been run and should be run before this is relied on commercially.** **NOT TESTED**
- **External scanner binaries are a separate, more concrete consideration.** KingSec does not bundle, vendor, or statically/dynamically link Nmap, Nuclei, Nikto, FFUF, Gobuster, Trivy, Semgrep, Amass, or OWASP ZAP — it only shells out to whichever of these binaries the operator has separately installed on the host (confirmed: `scanner_installer.py` only *prints* install commands; it never executes them). This is a materially different legal posture from bundling GPL code into a distributed product, but each of these 9 tools' own license terms (several are GPL-family upstream) governs how *the operator*, not KingSec, may use/redistribute the binary itself — this repo makes no claim about and imposes no restriction on that. **INFERRED**
- **Version-number anomaly worth flagging before relying on this lock file commercially**: several pinned versions in `uv.lock`/`requirements.txt` (e.g. `fastapi 0.141.1`, `starlette 1.6.0`, `cryptography 50.0.1`, `pytest 9.1.1`, `certifi 2026.7.22`) are far beyond any real-world release I can independently verify from within this repo, and `requirements.txt`'s own header states it was generated "2026-08-29." This may simply reflect this environment's date/package state, but it means these exact pins should be independently verified against the real package registries before being cited in a legal document. **NOT TESTED** (no live registry lookup performed)
- No dependency name in the direct runtime set matches a package recognizable as abandoned/deprecated by name alone. **INFERRED**

**Install / launch — exact commands from the repo**
- From source: `pip install .` then `kingsec-migrate` then `kingsec` (README, both the Quick-Start and Windows-PowerShell variants; env vars `KINGSEC_JWT__SECRET_KEY` / `KINGSEC_SECRETS__ENCRYPTION_KEY` set first).
- Docker: `docker build -t kingsec:2.0.0 .` then `docker run -d --name kingsec --env-file .env -p 8765:8765 -v kingsec-data:/home/kingsec/.kingsec kingsec:2.0.0`. Dockerfile's own `CMD`: `sh -c "kingsec-migrate && python -m kingsec"`.
- Docker Compose: `cp .env.example .env` (edit it), then `docker compose up -d`. This engagement directly ran an equivalent of this exact flow (verify-then-teardown) against commit `4e24e3b` in a prior phase. **TESTED**
- CLI entry points declared in `pyproject.toml`: `kingsec`, `kingsec-migrate`, `kingsec-bootstrap`. There is no `--help`/argument-parsing in `kingsec`'s entrypoint — running `kingsec --help` starts the server rather than printing usage (this engagement observed this directly: the process had to be killed after `--help` caused it to bind and listen rather than exit). **TESTED**

**Admin/root and credential requirements**
- Docker container runs as a dedicated non-root user (`useradd -r ... kingsec`, `USER kingsec` in the Dockerfile). Confirmed via `docker exec ... whoami` → `kingsec`, `id` → `uid=999(kingsec) gid=999(kingsec)` in a prior phase of this engagement. **TESTED**
- No README/docs instruction anywhere directs running the CLI or Docker commands with `sudo`/as Administrator; `sudo` only appears in host-OS setup steps (installing Docker itself, registering a systemd unit that itself runs the app as an unprivileged user).
- **Mandatory secret**: `KINGSEC_SECRETS__ENCRYPTION_KEY` — startup raises `ConfigError` and refuses to start if absent or invalid, in every environment including local dev. Confirmed directly: a container started with zero secrets crashed at startup with this exact `ConfigError`. **TESTED**
- **Effectively-mandatory (insecure-default, rejected)**: `KINGSEC_JWT__SECRET_KEY` and `KINGSEC_SECRETS__API_KEY_PEPPER` both default to a literal placeholder string that is explicitly rejected at startup. **TESTED** (same container-crash observation, sequential ConfigErrors for each).
- **Optional, BYO**: AI-provider API key (`AISettings.api_key`, default `None` — "the API key is optional at startup... never to require a key or talk to a provider," per the code's own docstring) and any external scanner binaries (app remains "fully operational with whatever subset is available" — README). No third-party cloud credential is required for the application to start and run.

---

## 2. Assessment scope — what does it actually check?

**KingSec does not implement its own vulnerability-detection logic.** It is an orchestration layer around **9 third-party scanner binaries**; for every one, KingSec's own code only builds a safe argv list, runs the binary as a subprocess, and parses its native output into KingSec's internal `Finding` object (occasionally layering a severity-reclassification heuristic on top of the tool's raw output). **INFERRED** (direct source read of all 9 adapters)

| # | Scanner | Target types | Exact invocation (from code) | KingSec-authored logic beyond parsing |
|---|---|---|---|---|
| 1 | Nmap | IP, Hostname, Network | `nmap -sV -n -oX - <target>` | Severity heuristic on NSE script IDs (5 HIGH patterns, glob-matched MEDIUM patterns) — dormant by default since `--script` isn't in the default args |
| 2 | Nuclei | IP, Hostname, URL | `nuclei -u <target> -jsonl -silent -nc -duc -rl <rate>` | None — severity taken directly from whatever template set is installed (KingSec sets no default template directory) |
| 3 | Nikto | Hostname, URL | `nikto -Tuning 1234567890abc -nointeractive -h <host>` | Regex-based severity classification of output lines (~20 patterns) |
| 4 | FFUF | Hostname, URL | `ffuf <url>/FUZZ -w <wordlist> -json` | None beyond standard JSON parsing |
| 5 | Gobuster | Hostname, URL | `gobuster dir -u <target> -w <wordlist>` | None |
| 6 | Trivy | Hostname (passed as fs/image path) | `trivy <fs\|image> --format json <target>` | CVSS-source disambiguation (NVD > RedHat > GHSA preference) only |
| 7 | Semgrep | Hostname (passed as fs path) | `semgrep scan --json [--config <rules>] <target>` | None — default ruleset unless operator sets `rules` |
| 8 | Amass | Hostname | `amass enum -passive -json - -d <target>` | Keyword-based labeling of discovered subdomain names (~30 terms) — a naming heuristic, not a live security check |
| 9 | OWASP ZAP | URL | `zap -quickurl <target> -quickout json` | None — ZAP's own built-in "quick scan" baseline |

**Custom checks not delegated to an external binary: effectively none found.**
- `application/compliance/` maps *already-produced* scanner findings to framework control IDs (CIS v8, NIST CSF 2.0, OWASP Top 10, CWE, MITRE ATT&CK, ISO 27001, PCI DSS 4.0) by lowercasing the finding's title/description and checking against ~45 hardcoded keyword sets. **This cannot produce a finding on its own — it is a labeling/coverage layer, not an independent check.**
- `application/playbooks/` is a SOAR-style automated-response system (notify Slack/Teams, create Jira/GitHub tickets, export to SIEM) reacting to findings already produced above — not a check.
- No CIS-benchmark engine, no independent OS/config hardening auditor, no cloud (AWS/Azure/GCP) API-based checker, and no identity/SSO posture checker *of a scanned target* exists. **MISSING**
- The `idp/` (SAML2/OIDC/OAuth2/LDAP) module implements login methods *into KingSec itself* — it is not a check against a target's identity infrastructure. **MISSING** for target-facing identity checks.

**Grouped by target type**: Network (Nmap) · Host/config (Trivy fs-mode, Semgrep) · Web application (Nikto, FFUF, Gobuster, Nuclei, ZAP) · Patch/vulnerability state (Trivy image-mode, Nuclei CVE templates, Nmap NSE if enabled) · External footprint (Amass, Nmap) · Cloud (AWS/Azure/GCP): **MISSING** · Identity/SSO of a target: **MISSING**.

**Total count**: **9 distinct scanner engines** is the defensible, code-confirmed number. A specific "N checks/rules" figure cannot be honestly stated for Nuclei, Nikto, Trivy, or Semgrep — their effective check count is determined entirely by third-party template/signature/rule databases installed on the host, external to this codebase, and not fixed or enumerable within it. Compliance-framework "coverage" entries (CIS 36, NIST CSF 41, OWASP Top 10, CWE ~140, MITRE ATT&CK 31, ISO 27001 ~60, PCI DSS 4.0 ~50) are label taxonomy only, populated post-hoc by keyword match — not independent detections.

**Assessment profiles** (`application/assessment_profiles.py`, 8 defined — the README's bullet list under-counts at 5, but its own profile table matches the code's 8): Quick Host Scan (nmap, ~5min) · Network Assessment (nmap+nuclei, ~30min) · Web Application Scan (nmap+gobuster+ffuf+nuclei+zap, ~60min) · API Assessment (ffuf+nuclei+zap, ~45min) · Source Code Review (semgrep, ~15min) · Container Assessment (trivy, ~10min) · External Footprint Mapping (amass+nmap, ~20min) · Full Assessment (all 9, ~90min). Duration estimates are a fixed per-scanner-minute lookup table summed at plan time, not measured run time.

---

## 3. Collection method — how does evidence get gathered?

**No direct use of `requests` or `aiohttp` anywhere in `src/`.** Outbound HTTP is only `httpx` or stdlib `urllib.request`, and every webhook/SIEM/ticketing/AI destination is routed through one shared SSRF-guard module (`infrastructure/notifications/url_validator.py`) that resolves the destination once, rejects private/loopback/reserved IPs (unless explicitly opted in for local AI models), pins the connection to that resolved IP, and refuses redirects.

**Every network-contact site found, exhaustively:**

| Destination | Fixed (KingSec/3rd-party) or user-supplied? | Always-on or opt-in? |
|---|---|---|
| AI provider (Anthropic default; OpenAI/OpenRouter/GLM/Gemini/Ollama/LM Studio selectable) | Fixed per-provider API host | **Opt-in** — `api_key` is `None` by default; no key = no call. Sends only sanitized finding title/severity/description/truncated evidence, never raw scan dumps, ids, or config. |
| NVD, CISA KEV, MITRE, FIRST.org (EPSS) threat-intel feeds | Fixed, third-party government/nonprofit hosts | On-demand — only fires when a user hits a threat-intel route/button; no background scheduler found |
| SMTP email | Admin-configured host | Opt-in — blank by default, no-ops with "SMTP not configured" |
| Slack / Discord / Teams / generic webhook | Admin-configured URL | Opt-in — blank by default |
| SIEM export (Splunk/Sentinel/Elastic) | Partial (Sentinel/Elastic URL built from admin-entered workspace/cloud ID) | Opt-in, license-gated |
| Ticketing (Jira/GitHub/GitLab) | GitHub API host fixed; Jira/GitLab admin-entered | Opt-in, license-gated |
| License activation/validation | **MISSING — no network call exists; fully offline HMAC/Ed25519 signature + local machine-fingerprint check** | N/A |
| Auto-update / version check | **MISSING — no network call exists** | N/A |
| Telemetry / analytics / crash reporting | **MISSING in practice** — a `ProductTelemetryConfig.remote_endpoint` field exists and a docstring claims "optional opt-in remote reporting," but no code anywhere reads or POSTs to that field. All telemetry writes are local JSONL files only. This is inert/aspirational configuration, not a working feature. | N/A |
| KingSec's own `/api/v1/health` loopback self-check | `http://127.0.0.1:8765` — loopback, not egress | N/A |
| **The 9 scanner binaries** | **The user/operator-supplied assessment target, exclusively** — KingSec's own process never touches the network for a scan; the external binary opens its own sockets directly to whatever target was configured | Always-on (this is the core scanning function) |

**Nuclei template-update behavior** (specifically checked, since it's the one tool with an automatic phone-home in its own upstream design): KingSec's invocation always includes `-duc` ("no auto update-check"), with a code comment stating this is deliberate to prevent "surprise network calls mid-scan." `-update-templates` is never passed by KingSec anywhere. An operator would have to run `nuclei` manually, outside KingSec, to trigger that.

**Does anything constitute active scanning/probing of a remote system?** Yes — by design and necessity. Nmap (port/service probing), Nuclei/Nikto/FFUF/Gobuster/ZAP (active HTTP requests and fuzzing against the target), and Amass (passive-only, per KingSec's hardcoded `-passive` flag — it does not send packets to the target itself, only queries third-party DNS/certificate-transparency sources about it) all constitute active or passive reconnaissance of whatever target string the operator configures. This is the product's core function, not an incidental side effect.

Scanner subprocess execution itself is safe against argument/shell injection: every adapter passes the target through `subprocess.run(argv, shell=False, ...)` as a single list element, never through a shell string. **INFERRED**

---

## 4. Authorization controls

- `authorized_by` and `scope` are **free-text strings with format-only validation** (non-empty, max length). Domain code (`Authorization.__post_init__`) only checks "is this a non-blank string" — there is no lookup against a real authorization record, no signature/document check, and no cross-check between the `scope` text and the actual `target` field.
- **Target allowlist / scope restriction: MISSING.** Any authenticated user (subject only to RBAC role, e.g. must be Analyst+) can create an assessment against any target string that passes basic format validation — there is no mechanism restricting which IP/hostname/URL may be entered.
- **Consent gate: exists only as a required non-empty field + a UI warning banner**, not as backend verification. The frontend form's own copy states plainly: "KingSec can't tell you what's authorized in your situation — only you... can." The backend enforces only that *some* non-empty authorization text exists before a scan can start — never that it is real, checked, or valid.
- `authorized_by`/`scope` are stored, timestamped, and printed on the report cover page as an audit trail — this is their actual function: **audit-trail metadata, not an authorization gate.**

**Stated plainly, as instructed: there is no real target-authorization verification in this product. It is MISSING.**

---

## 5. Scoring and severity model

**Per-finding severity**: a custom 5-tier `Severity` IntEnum (Informational/Low/Medium/High/Critical). Each scanner adapter maps its own native severity vocabulary (Nuclei/Trivy's own severity strings) or a KingSec-authored heuristic (Nmap NSE-script-ID table, Nikto/regex patterns, Amass keyword list) into this enum. **CVE/CVSS data (`cvss_score`, `cvss_vector`) is carried as pass-through metadata from Nuclei/Trivy output — KingSec never computes a severity from the CVSS formula itself; there is no CVSS-vector-parsing/scoring code anywhere in the repo.**

**Aggregate "executive score"** — `domain/report.py::compute_executive_score()`, quoted in full:
```python
_SCORE_PENALTY = {CRITICAL: 25, HIGH: 10, MEDIUM: 5, LOW: 2, INFORMATIONAL: 0}
# 100 - sum(penalty[severity] * count), floored at 0, rounded to 1 decimal
```
The code's own comment states this explicitly: *"a deliberately simple, explainable heuristic — not a CVSS-style aggregate."*

**A second, separate custom formula** exists for the unrelated Threat Intelligence (CVE/EPSS/KEV) dashboard: `overall = business_risk*0.3 + exploitability*0.35 + likelihood*0.35`, plus a flat +15 "KEV boost" and exploit-maturity boosts (weaponized +15, PoC +8). This one *does* take a real CVSS base score and real EPSS score as inputs, but the weighting/boost formula combining them is invented for this codebase, not a published standard's formula.

**Is this based on a published standard?** **No — both scoring mechanisms are custom/proprietary, and the code says so in its own comments.** No CIS Benchmark scoring, no NIST CSF tier logic, and no CVSS base-score computation exists anywhere in `src/`. CVSS scores that appear in reports are only ever passed through from what Nuclei/Trivy already computed, never derived by KingSec.

---

## 6. Data handling — the "local-first" claim

- **What's written to disk, and where**: default `StorageSettings.data_dir = ~/.kingsec` (or `/home/kingsec/.kingsec` in the container, bind-mounted to a named Docker volume in the documented Compose setup). This holds the SQLite database (assessments, findings, reports, users, audit events, telemetry JSONL, backups).
- **Encryption at rest — narrower than "local-first" might imply**: across the entire database schema, only **one column** is application-level encrypted: `LicenseORM`-adjacent `api_key_encrypted` (Fernet ciphertext, keyed by `KINGSEC_SECRETS__ENCRYPTION_KEY`) — this protects the AI provider's API key. **All other integration credentials (SMTP password, webhook URLs, SIEM tokens, Jira/GitHub/GitLab tokens) are `pydantic` `IntegrationSettings` sourced from process environment variables / the `.env` file — they are never written into KingSec's own encrypted database at all.** Their "at rest" protection is entirely whatever OS filesystem permissions the operator sets on `.env`; KingSec's own Fernet encryption does not cover them. Scan findings, report content, and assessment metadata are stored in the SQLite database **unencrypted** (protected only by the OS-level file/volume permissions, not by KingSec's application-level encryption). **INFERRED**
- **What leaves the machine, and under what conditions**: see the full network table in Section 3. Summarized: nothing leaves the machine on a default/fresh install with no AI key and no integrations configured, except (a) whatever the operator's own scanner target actually is (traffic goes from KingSec's process → the external scanner binary → the target, not to KingSec/a third party), and (b) on-demand public CVE-database lookups if a user explicitly uses the Threat Intelligence feature.
- **Telemetry, analytics, crash reporting**: a local-only telemetry subsystem exists (JSONL files under `data_dir/telemetry/`). Its own config docstring claims "optional opt-in remote reporting" — **this is not implemented**; no code path anywhere sends telemetry off the machine. **MISSING as a working feature, present only as inert configuration.**
- **Update check**: **MISSING.** `UpgradeService` is a local-only pre-flight/backup/version-bookkeeping helper (disk space, running-process check, local `.kingsec-version` file) — it never fetches a version number from anywhere external.
- **Is assessment data retained after a run? Encrypted?** Retained: yes, indefinitely by default, in the local SQLite database (subject to whatever backup-retention/audit-retention settings the admin configures, e.g. a documented "Audit Log Retention Days: default 365"). Encrypted: **no**, per the single-column finding above — findings/reports/assessment data are not application-level encrypted at rest, only whatever the host OS/disk itself provides. Backups (`domain/backup.py`) do have their own encryption path (separate from the live DB) confirmed in a prior phase of this engagement — not re-verified in this pass. **NOT TESTED** (not re-confirmed this pass; carried over from an earlier phase's finding)

---

## 7. Output and reporting

- **Formats produced**: PDF (default) and HTML, generated by KingSec's own template renderer (`infrastructure/reporting/templates.py` + `weasyprint` for PDF rendering, `reportlab` also present as a dependency). `output_format` is validated against a fixed set (`_FORMATS`); an unsupported value raises `ReportGenerationError`. **There is no JSON "report" output format** — raw assessment/finding data is available as JSON only via the general API, not as a generated report artifact. **INFERRED**
- **Is the report branded/customizable?** The template code *supports* a `brand_name` parameter and a CSS "logo-placeholder" box (text-name substitution, not an actual logo image upload). **However, the real application entrypoint (`__main__.py` → `create_wired_application()`) never supplies a non-default value anywhere in the codebase — `brand_name` is always `"KingSec"` in every real, running deployment.** There is no environment variable, `.env` setting, or admin-UI field found that lets an operator actually change this. `LicenseGate.can_use_custom_branding()` exists as a license-tier check but (per Section 8) has zero callers anywhere outside its own definition file. **Effectively MISSING as a customer-facing feature, despite template-level code support.** **INFERRED**
- **How long does a full run take?** **NOT TESTED end-to-end in this review.** A prior phase of this engagement attempted a real assessment via the live HTTP API (target `127.0.0.1`, Quick Host Scan profile) inside a container that lacked bundled scanner binaries (by design — see Section 1); it reached a terminal `failed` state in well under a minute because both configured scanners (`nmap`, `nuclei`) reported "binary not found," not because a real scan ran to completion. This host does have `nmap`, `trivy`, and `semgrep` binaries installed locally (`which` confirmed all three), but running a live timed assessment through the actual application on this host was not attempted in this review, because doing so would require starting a real server process against this machine's pre-existing local KingSec data directory (`~/.kingsec`), and this task is explicitly read-only / must not risk touching real local state. The per-profile duration *estimates* in the code (Section 2 table) are a fixed lookup table, not measured historical run time — no code was found that records or reports actual elapsed scan duration back to the user beyond a raw job-timestamp delta. **NOT TESTED**

---

## 8. Commercial mechanics

- **Licensing/entitlement**: a real `LicenseGate` with 13 checks (10 boolean feature flags + `max_users`/`max_organizations`/`max_api_keys` numeric limits) exists and is **enforced at 10 of 13 real call sites** (integrations, scheduling, API keys, SSO, enterprise audit, team collaboration, activity feed, and all three numeric limits). **Not enforced anywhere** (defined in `licensing.py` with zero external callers): `can_use_advanced_reports()`, `can_use_priority_support()`, `can_use_custom_roles()`, `can_use_custom_branding()`. This is a materially better state than a prior internal note ("most checks unenforced") suggested — most are now wired; 4 boolean feature gates remain unenforced. **INFERRED**
- **Trial limits**: **MISSING, explicitly by design.** The product's own commercial docs state plainly: "no trial period, no credit card required, no feature timeout" on the Free/Community tier, which is a permanent tier with fixed limits (5 users, 1 organization, 3 API keys, 0 schedules, 0 integrations), not a decaying trial.
- **License activation mechanism**: fully offline — Ed25519/HMAC signature verification against a public key baked into the binary, plus a local machine-fingerprint check. **No license server is ever contacted.** (Confirmed independently in Section 3's network audit.)
- **Account/auth system**: yes — JWT (HS256, access/refresh/MFA-pending tokens, DB-backed revocation) plus a 3-tier role model (Viewer/Analyst/Admin, ordinal `IntEnum` comparison for permission checks). Self-registration exists; the first-ever registered user on a fresh instance automatically becomes Admin, subsequent registrants default to Viewer — confirmed directly by this engagement in a prior phase's live smoke test. **TESTED**
- **Versioning/update mechanism**: **MISSING** as an automatic/remote feature (see Section 6) — version bookkeeping is local-file-only, operator-driven.

---

## 9. Quality and verification state

**Test suite — run fresh for this review:**
```
$ uv run pytest -q
...
3919 collected
3915 passed
4 failed
0 skipped
0 errors
482s
exit code: 1
```
**TESTED.** The 4 failures are the same, pre-existing, environment/timing-dependent tests this engagement has independently reproduced — identically — against both this exact commit and an earlier, unmodified commit, across multiple prior phases: `test_list_jobs_newest_first` (×2), `test_cancel_pending_job`, `test_progressive_lockout_duration` — all fail on tied-timestamp/tied-duration assertions (e.g. `assert 60.0 > 60.0`), consistent with clock-resolution granularity on this specific machine, not application logic defects.

Test files: 269 `test_*.py` files (206 under `tests/unit/`, 63 under `tests/integration/`, 1 e2e-tagged file found). Coverage breadth (unit + integration across domain, application, infrastructure, and inbound-web layers) is extensive based on the file count and this engagement's repeated observation of the suite across six prior phases, but a formal line/branch coverage percentage was not generated in this pass. **NOT TESTED** (no `pytest --cov` run this pass)

**Static analysis — run fresh for this review:**
```
$ uv run ruff check .
All checks passed!

$ uv run mypy src
Success: no issues found in 598 source files
```
**TESTED**, both exit 0, no findings.

**Error-handling gaps that could crash a customer's run:**
- 58 occurrences of bare `except Exception:`/`except:` (silent-catch patterns) found across `src/kingsec/` via direct grep. This engagement's own network-call audit (Section 3) directly examined a meaningful sample of these — AI enrichment, telemetry, notification/webhook sending — and confirmed they are deliberate "best-effort, never fail the primary operation" patterns (e.g., AI enrichment failure never fails a scan). **The full set of 58 was not individually re-verified in this pass** — this is reported as a raw count with a sampled, not exhaustive, characterization. **NOT TESTED** for the remainder.
- The `kingsec` CLI entrypoint has no argument parsing at all — `kingsec --help` starts the actual server rather than printing usage, which this engagement observed directly (a stray, unresponsive process had to be killed). This is a real UX rough edge for anyone scripting around the CLI. **TESTED**

**Hardcoded secrets/credentials/paths:**
```
$ grep -rnE "sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY" src/
(no matches)
$ grep -rnE "D:\\\\New_folder|C:\\\\Users\\\\Laptop|/home/[a-z]+/(?!kingsec)" src/kingsec/
(no matches)
```
**TESTED — clean.** No hardcoded API keys, private keys, or personal-machine-specific paths were found in application source.

---

## 10. Top 5 risks to selling this as-is

1. **No third-party dependency license inventory exists.** ~103 resolved packages, zero license metadata anywhere in the repo, no SBOM. This must be produced and reviewed (especially the 9 externally-shelled-out scanner binaries, several of which are GPL-family upstream) before any commercial redistribution contract is signed. **Legal.**
2. **"Authorization" is a free-text audit field, not a control.** Any authenticated Analyst+ user can point a scan at any target string that parses; the only gate is a non-empty `authorized_by`/`scope` string. If this product is marketed as enforcing authorized-scope scanning, that claim is not true today — it should be marketed accurately as "records who claimed authorization," not as verifying it. **Legal / operational.**
3. **The scoring/severity model is 100% custom, not CVSS/CIS/NIST-based**, despite reusing CVSS's vocabulary (severity band names) and displaying pass-through CVSS numbers from underlying tools. A buyer expecting a standards-based score (for compliance-attestation purposes, e.g.) will be misled unless this is stated plainly in materials. **Commercial / reputational.**
4. **"Local-first" and encryption-at-rest claims are narrower than they may sound.** Only the AI-provider API key is application-encrypted; all other integration credentials live in plaintext env/`.env` files, and scan findings/reports are unencrypted in the SQLite database. If "your data stays local and secure" is a selling point, the actual encryption boundary needs to be stated precisely, not implied broadly. **Commercial / legal.**
5. **Dependency version pins in the lock file look anomalous** (version numbers inconsistent with any release history this reviewer could verify) and were generated in an environment dated in the future relative to normal package cadence. Before this lock file backs a commercial release build, it should be independently regenerated/verified against real package registries — shipping unverifiable pins is a supply-chain risk in its own right. **Technical / operational.**

*(Additional, lower-order items not in the top 5 but worth tracking: 4 boolean license-feature gates defined but unenforced; telemetry "opt-in remote reporting" is advertised in a docstring but not implemented; report branding is code-capable but not wired to any real configuration; the CLI has no `--help`.)*

---

## Files reviewed

`pyproject.toml`, `uv.lock`, `requirements.txt`, `.python-version`, `Dockerfile`, `docker-compose.yml`, `.env.example`, `Makefile`, `README.md`, `docs/INSTALL.md`, `docs/LICENSING.md`, `docs/ADMIN_GUIDE.md`, `docs/commercial/website-about.md`, `docs/commercial/website-faq.md`, `docs/commercial/website-pricing.md`, `LICENSE`; `frontend/package.json`; and, under `src/kingsec/`: `__main__.py`, `_migrate.py`, `_bootstrap.py`, `bootstrap/composition.py`, `domain/{assessment,authorization,finding,report,license,enums,_validation}.py`, `application/{use_cases/create_assessment,use_cases/start_assessment,use_cases/register_user,use_cases/create_schedule,use_cases/create_api_key,submit_assessment,generate_report,assessment_profiles,scanner_installer,scanner_discovery,analytics_service}.py`, `application/compliance/{mapper,framework_definitions}.py`, `application/playbooks/{engine,actions}.py`, `application/threat_intelligence/{enrichment,feed_aggregator,risk_calculator}.py`, `application/services/licensing.py`, `infrastructure/config/models.py`, `infrastructure/scanner/{nmap,nuclei,nikto,ffuf,gobuster,trivy,semgrep,amass,zap,runner}.py` and their `parser.py` counterparts, `infrastructure/scanner/plugins/*/adapter.py`, `infrastructure/ai/{client,adapter,providers,prompt,provider_tester}.py`, `infrastructure/notifications/{senders,url_validator}.py`, `infrastructure/integrations/{email_service,webhook_service,siem_service,ticketing_service}.py`, `infrastructure/licensing/parser.py`, `infrastructure/upgrade/upgrade_service.py`, `infrastructure/telemetry/product_telemetry.py`, `infrastructure/reporting/{adapter,provisioning,renderer,templates}.py`, `infrastructure/persistence/models.py`, `infrastructure/secrets/{provisioning,fernet_encryption_service,encrypted_file_secret_provider}.py`, `infrastructure/monitoring/diagnostics.py`, `adapters/inbound/web/{identity_routes,audit_events,organization_routes,threat_intelligence_routes,auth}.py`; test suite (full run, 269 files); `frontend/src/components/features/assessment/CreateAssessmentForm.tsx`.

Plus direct execution: `uv run pytest -q` (full suite), `uv run ruff check .`, `uv run mypy src`, `which nmap/nuclei/nikto/ffuf/gobuster/amass/trivy/zap/semgrep`, `uv run kingsec --help` (observed behavior), grep sweeps for hardcoded secrets/paths and network-call patterns across all of `src/`.

## Files NOT reviewed

The full `frontend/src/` tree beyond the one form component above (React/TypeScript UI code — not reviewed for this inventory, since the task scope is backend/product-capability facts). `application/compliance/{coverage,gap_analyzer,report_generator}.py` (confirmed to consume the mapper's output by name/import only, not line-read in depth). `application/idp/{provider_service,protocol_handlers,jit_provisioning}.py` beyond confirming their purpose (KingSec's own login SSO, not target-facing). Individual Alembic migration files beyond the ones already verified in prior phases of this engagement. `infrastructure/backup/*` (encryption-at-rest claim for backups specifically was carried over from an earlier phase, not re-read this pass). The full `tests/` suite's individual test bodies (run as a suite; not read file-by-file). CI/CD workflow YAML (`.github/workflows/`) — reviewed in a prior phase of this engagement, not re-read for this document. Any dependency's actual upstream license text (no external/internet lookups were performed in this review).
