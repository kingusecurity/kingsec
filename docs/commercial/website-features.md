# KingSec v1.1.0 — Features

---

## Assessment Engine

- **Pre-configured profiles** — Six built-in assessment profiles map to real-world workflows:
  - Quick Host Scan (~5 min)
  - Network Assessment (~30 min)
  - Web Application Scan (~60 min)
  - API Assessment (~45 min)
  - External Footprint (~20 min)
  - Full Assessment (~90 min)
- **Profile-free assessments** — Skip the profile entirely and KingSec runs every scanner compatible with your target type.
- **Scheduled assessments** — Run assessments on a one-time or recurring schedule.
- **Concurrent execution** — Multiple assessments can run simultaneously with configurable parallelism.
- **Progress tracking** — Real-time status updates per scanner and per target.

---

## Scanner Orchestration

- **Plugin-based architecture** — Each scanner is a self-contained plugin, added via a documented interface without touching the orchestration core.
- **Six scanners, wired into every profile** — Nmap, Nuclei, Nikto, FFUF, Gobuster, OWASP ZAP. (Trivy, Semgrep, and Amass are also registered as plugins in the codebase but are not currently reachable through any assessment profile.)
- **Normalized output** — All scanner results are parsed into a common schema: target, finding type, severity, evidence, and timestamp.
- **Deduplication** — Findings from multiple scanners targeting the same asset are merged and correlated.
- **Isolated execution** — Scanners run in separate processes. A crash in one scanner does not affect others.

---

## AI Enrichment

- **Bring-your-own-key** — Connect your own OpenAI, Anthropic, or compatible API key. No vendor lock-in.
- **Context-aware analysis** — AI evaluates findings in the context of your assessment profile and target type.
- **Remediation guidance** — Natural-language steps for addressing each finding, including code snippets where relevant.
- **Severity clarification** — AI can explain why a finding is rated a given severity and what real-world impact it may have.
- **Privacy-preserving** — Only finding title, severity, description, and evidence snippets — redacted before sending — go to the AI provider. Raw scan data stays local.
- **Toggleable** — AI enrichment is optional and can be enabled per-assessment or globally.

---

## Reporting

- **HTML and PDF export.**
- **On-demand reports** — Generate a report for any completed assessment.
- **Scheduled reports** — Automatically generate and export reports on a cadence.
- **Executive summaries** — Each report includes a high-level overview suitable for non-technical stakeholders.
- **Technical appendices** — Full finding details, evidence, and raw scanner output included in extended reports.

---

## Security

- **JWT authentication** — Stateless token-based auth with configurable expiration.
- **Role-based access control** — Admin, Analyst, Viewer roles with granular permission sets.
- **Multi-factor authentication** — TOTP-based MFA support.
- **Local-first deployment** — All data resides on your infrastructure. No cloud sync, no telemetry, no third-party data processing.
- **Safe by default** — Binds to `127.0.0.1:8765` only. Not exposed to the network unless explicitly configured otherwise.
- **Audit logging** — User actions, assessment runs, and configuration changes are logged.

---

## Administration

- **Built-in React frontend** — Dashboard, Assessments, Findings, Reports, Settings, and Admin panels.
- **User management** — Create, suspend, or delete users. Assign roles and teams.
- **Team management** — Group users into teams with shared assessment scope and report visibility.
- **System configuration** — Scanner paths, AI provider settings, authentication policies, and global defaults configured through the Admin panel or JSON config file.
- **Docker deployment** — Single container with persistent volume mounts for data and configuration.
- **pip deployment** — Install directly via `pip install kingsec` for native execution.
- **Health monitoring** — System status page showing scanner availability, queue depth, and resource usage.

---

## Deployment

- **Docker image** — Published on Docker Hub: `kingusecurity/kingsec`
- **PyPI package** — Install via `pip install kingsec`
- **System requirements** — Linux x86_64 or arm64, 4 GB RAM minimum (8 GB recommended), 10 GB disk.
- **Data persistence** — SQLite database stored in configurable data directory. Full backup and restore support.
- **No external dependencies** — No cloud account, no registration, no license server communication.

---

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
