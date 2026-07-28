# KingSec v1.1.0 — Product Messaging Artifacts

---

## 30-Second Elevator Pitch

"KingSec is a local-first, AI-augmented vulnerability management platform for small and medium businesses. It orchestrates nine industry-standard security scanners — Nmap, Nuclei, Nikto, and others — under a single web interface that runs entirely on your own infrastructure. Your data never leaves your network unless you choose to enable AI analysis with your own API key. Eight pre-configured assessment profiles let you start scanning in under a minute. Reports export in JSON, HTML, PDF, CSV, or Markdown. It's free to use, and it's built for organizations that want professional-grade security tooling without sending their data to a third party."

---

## 2-Minute Product Demo Script

**Setup:** Docker already running with KingSec container. Browser open to `http://127.0.0.1:8765`. Logged in as admin.

**Slide 1 — Dashboard (0:00–0:15)**
"This is the KingSec dashboard. It shows recent assessments, finding summaries by severity, and system status. From here you can navigate to any section — Assessments, Findings, Reports, Settings, or Admin."

**Slide 2 — Creating an Assessment (0:15–0:35)**
"Let's run a Quick Host Scan. I click 'New Assessment,' select the Quick Host Scan profile — pre-configured to run Nmap and Nuclei against a target. Estimated time: about five minutes. I enter a target IP and click Start."

**Slide 3 — Live Progress (0:35–0:50)**
"The assessment page shows live progress — which scanner is currently running, what it found so far, and estimated completion. Scanners execute sequentially or in parallel depending on the profile."

**Slide 4 — Findings (0:50–1:10)**
"Once complete, findings appear in the Findings tab. Each finding has a title, severity, affected asset, and timestamp. I can filter by scanner, severity, or target. Let's open one."

**Slide 5 — AI Enrichment (1:10–1:30)**
"With AI enrichment enabled — using my own API key — I can click 'Analyze with AI' to get remediation guidance. This shows natural-language steps for addressing the finding, along with context about why it matters. No AI provider sees raw scan data — only the finding metadata."

**Slide 6 — Reports (1:30–1:45)**
"Back in Reports, I can generate an executive summary or a detailed technical report. Choose from JSON, HTML, PDF, CSV, or Markdown. One click downloads."

**Slide 7 — Wrap-up (1:45–2:00)**
"That's the core workflow. Scans run on your hardware, data stays local, AI is optional and BYO-key. Setup takes one Docker command. Deploy it today at no cost."

---

## 5-Minute Presentation Outline

### Slide 1 — Title Slide
- KingSec v1.1.0
- Local-first, AI-augmented ASM/VM for SMBs
- Author: Abdul Mannan

### Slide 2 — The Problem
- SMBs lack budget and headcount for enterprise VM tools
- SaaS scanners expose sensitive data to third parties
- Stitching together free tools is time-consuming and error-prone

### Slide 3 — The Solution
- KingSec: unified platform, local-first architecture
- Nine scanners under one interface
- Optional AI enrichment, BYO-key

### Slide 4 — Key Design Principles
- Local-first & private — data never leaves your infrastructure by default
- BYO-AI-key — you choose the provider
- Honest by design — no dark patterns or data harvesting
- Safe by default — binds to localhost, auth required

### Slide 5 — Scanner Framework
- Plugin architecture: Nmap, Nuclei, Nikto, FFUF, Gobuster, Trivy, Semgrep, Amass, OWASP ZAP
- Normalized output, deduplication, correlation
- Add or remove scanners without touching core

### Slide 6 — Assessment Profiles
- 8 pre-configured profiles (30 sec–90 min)
- Quick Host Scan, Network Assessment, Web App, API, Code Review, Container, External Footprint, Full Assessment
- Custom assessments also supported

### Slide 7 — AI Enrichment
- Connect OpenAI, Anthropic, or compatible API
- Remediation guidance, severity explanation, context-aware analysis
- Toggleable per assessment; only metadata sent to provider

### Slide 8 — Reporting & Export
- JSON, HTML, PDF, CSV, Markdown
- On-demand or scheduled
- Executive summaries + technical appendices

### Slide 9 — Security & Access Control
- JWT auth, RBAC, MFA/TOTP
- Audit logging
- No phone-home, no telemetry, no license server

### Slide 10 — Deployment
- Docker: `docker run -p 127.0.0.1:8765:8765 kingusecurity/kingsec`
- pip: `pip install kingsec && kingsec serve`
- Requirements: Linux, 4 GB RAM, 10 GB disk
- SQLite persistence, no external DB needed

### Slide 11 — Pricing
- Free tier: all scanners, all profiles, up to 3 users
- Professional: RBAC, teams, unlimited schedules — $49/mo placeholder
- Enterprise: custom plugins, white-label, SLA

### Slide 12 — Call to Action
- Download: `docker pull kingusecurity/kingsec`
- Documentation: GitHub repo
- Contact: kingusecurity@gmail.com
- GitHub: https://github.com/kingusecurity/kingsec

---

## Sales One-Pager

**Product:** KingSec v1.1.0 — Local-First ASM/VM Platform

**Tagline:** Your Infrastructure. Your Data. Your AI.

**One-line summary:** A privacy-first vulnerability management platform that runs on your hardware, orchestrates nine scanners, and optionally augments findings with your own AI provider.

**Key differentiators:**
- Local-first: all data stays on your infrastructure
- BYO-AI-key: no vendor lock-in on AI provider
- Nine bundled scanners: Nmap, Nuclei, Nikto, FFUF, Gobuster, Trivy, Semgrep, Amass, OWASP ZAP
- 8 pre-configured assessment profiles: 5 min to 90 min
- Multi-format reports: JSON, HTML, PDF, CSV, Markdown
- Auth: JWT, RBAC, MFA/TOTP

**Who it's for:**
- IT administrators managing security for an SMB
- Security analysts who want unified findings from multiple tools
- MSSPs delivering VM services to SMB clients
- Business owners who need visibility into risk posture without exposing data to third parties

**Quick start:**
```
docker run -p 127.0.0.1:8765:8765 kingusecurity/kingsec
```
Then open `http://127.0.0.1:8765`.

**Pricing:** Free (fully functional, up to 3 users). Professional ($49/mo) adds RBAC, teams, unlimited schedules. Enterprise (custom) adds custom plugins, white-label, SLA.

**Contact:** kingusecurity@gmail.com | https://github.com/kingusecurity/kingsec

---

## Executive Summary (For Decision-Makers)

**Problem**
Small and medium businesses need vulnerability management capabilities but cannot justify the cost, complexity, or data privacy risk of enterprise solutions or SaaS-based scanners. Existing approaches either expose sensitive network data to third parties or require significant manual effort to correlate output from multiple free tools.

**Solution**
KingSec is a local-first, AI-augmented attack surface management platform that runs entirely on the organization's own infrastructure. It orchestrates nine open-source security scanners under a single web interface, normalizes findings, and presents a unified view of vulnerability posture. AI enrichment is optional, bring-your-own-key, and privacy-preserving.

**Key advantages**

- **Data sovereignty.** All scanning, processing, and storage occurs on-premises. No data is transmitted to external services unless AI enrichment is explicitly enabled with a user-provided API key.
- **Cost efficiency.** Core functionality is free. The only variable cost is optional AI API usage, billed directly by the chosen provider. No per-asset, per-finding, or per-seat licensing.
- **Operational simplicity.** One Docker command deploys the full platform. Eight pre-configured assessment profiles cover common workflows. Reports export in five formats with a single click.
- **Scalable security.** RBAC, team management, and audit logging support organizations from solo practitioners to multi-team environments. Scheduled assessments and automated reporting reduce manual overhead.

**Business impact**
- Reduce tooling costs by replacing 5–10 standalone scanning tools.
- Eliminate data privacy risk by keeping scan results on-premises.
- Cut assessment-to-report time from hours to minutes.
- Provide stakeholders with clear, actionable reports without manual aggregation.

**Next steps**
- Deploy the Free tier today with one Docker command.
- Evaluate Professional tier features for team environments.
- Contact kingusecurity@gmail.com for Enterprise inquiries.

---

## Technical Overview

### Architecture

KingSec uses a monolithic server architecture with a plugin-based scanner framework:

```
┌─────────────────────────────────────────────┐
│              React Frontend                  │
│    (Dashboard, Assessments, Findings,        │
│     Reports, Settings, Admin)                │
└──────────────────┬──────────────────────────┘
                   │ HTTP (127.0.0.1:8765)
┌──────────────────▼──────────────────────────┐
│            Python Backend (FastAPI)          │
│  ┌─────────┐ ┌──────────┐ ┌──────────────┐ │
│  │ Auth    │ │Assessment│ │ Report Engine │ │
│  │ (JWT,   │ │ Engine   │ │ (JSON/HTML/   │ │
│  │  MFA)   │ │          │ │  PDF/CSV/MD)  │ │
│  └─────────┘ └────┬─────┘ └──────────────┘ │
│                   │                          │
│  ┌────────────────▼──────────────────────┐  │
│  │       Scanner Orchestrator            │  │
│  │  ┌─────┐ ┌──────┐ ┌─────┐ ┌──────┐  │  │
│  │  │Nmap │ │Nuclei│ │Nikto│ │ FFUF │  │  │
│  │  └─────┘ └──────┘ └─────┘ └──────┘  │  │
│  │  ┌──────┐ ┌──────┐ ┌───────┐        │  │
│  │  │Gobust│ │Trivy │ │Semgrep│        │  │
│  │  └──────┘ └──────┘ └───────┘        │  │
│  │  ┌─────┐ ┌────────┐                 │  │
│  │  │Amass│ │ZAP     │                 │  │
│  │  └─────┘ └────────┘                 │  │
│  └─────────────────────────────────────┘  │
│                   │                          │
│  ┌────────────────▼──────────────────────┐  │
│  │           SQLite Database             │  │
│  │  (findings, config, users, sessions)  │  │
│  └───────────────────────────────────────┘  │
│                   │                          │
│  ┌────────────────▼──────────────────────┐  │
│  │         AI Enrichment Module          │  │
│  │  (OpenAI / Anthropic / compatible)    │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### Technology Stack

| Component | Technology |
|---|---|
| Frontend | React (built-in, served by the backend) |
| Backend | Python (FastAPI) |
| Database | SQLite (via SQLAlchemy) |
| Authentication | JWT (PyJWT), TOTP (pyotp) |
| Scanner execution | Subprocess with timeout/ isolation |
| AI integration | OpenAI / Anthropic API (HTTP) |
| Packaging | Docker (multi-arch), PyPI |
| Configuration | JSON config file + environment variables |

### Deployment Options

**Docker (recommended):**
- Single container: `kingusecurity/kingsec`
- Port: `127.0.0.1:8765` (configurable)
- Volume mount: `/data` for persistence
- Supported architectures: linux/amd64, linux/arm64

**pip:**
- Package: `kingsec`
- Python: 3.9–3.12
- Command: `kingsec serve`
- Data directory: configurable via `--data-dir`

### Data Flow

1. User creates an assessment via the React frontend
2. Backend persists the assessment record and starts the scanner orchestrator
3. Orchestrator executes each configured scanner as a subprocess
4. Scanner output is parsed and normalized into a common finding schema
5. Findings are deduplicated and stored in SQLite
6. Optional: user requests AI enrichment — finding metadata is sent to the configured AI provider
7. User generates reports from findings in any of five output formats

### Security Properties

- Server binds to `127.0.0.1` only by default
- No outbound connections except (optional) AI API calls
- No telemetry, analytics, or crash reporting
- JWT tokens with configurable expiration
- Passwords hashed with bcrypt
- TOTP secrets stored encrypted at rest
- No license server communication

---

**Version:** 1.1.0  
**Author:** Abdul Mannan  
**Contact:** kingusecurity@gmail.com  
**GitHub:** https://github.com/kingusecurity/kingsec
