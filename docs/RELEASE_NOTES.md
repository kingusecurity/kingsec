# KingSec v2.0.0 — Release Notes

**Release Date:** July 30, 2026
**Version:** 2.0.0 (General Availability)
**License:** Proprietary — All Rights Reserved

---

## What's New in KingSec v2.0.0

KingSec v2.0.0 is the General Availability release of our local-first, AI-augmented Attack Surface Management and Vulnerability Management platform. This release consolidates 33 phases of development into a production-ready product.

### Core Capabilities

- **Attack Surface Management** — Automated discovery and inventory of internet-facing assets, exposures, and technologies
- **Vulnerability Management** — Multi-scanner integration (Nuclei, Nmap, Nikto, Trivy, ZAP, Semgrep, Amass, Gobuster, ffuf)
- **AI-Powered Copilot** — Conversational AI assistant for security analysis, playbook creation, and investigation notes
- **Automated Playbooks** — Custom automation workflows with trigger-action patterns
- **Real-Time Monitoring** — Continuous monitoring with alerting and timeline visualization
- **Threat Intelligence** — CVE explorer, KEV integration, and threat feed aggregation
- **Compliance Dashboard** — Framework-based compliance tracking and reporting
- **Asset Inventory** — Centralized asset management with tagging and relationship mapping

### Enterprise Features

- **SSO Integration** — SAML/OIDC identity provider configuration and connection testing
- **Role-Based Access Control** — Viewer, Analyst, and Admin roles with granular permissions
- **Audit Trail** — Complete activity logging with export capabilities
- **Plugin SDK** — Extensible plugin system with sandboxed execution
- **Distributed Workers** — Multi-node task processing with job queuing
- **Backup & Restore** — Automated backup with point-in-time recovery

### Security Hardening

- SSRF protection on all outbound HTTP clients
- Plugin sandboxing with filesystem isolation, execution timeout, and memory limits
- Account lockout with progressive delays (60s → 120s → 300s → 600s)
- Input validation against SQL injection, XSS, and path traversal
- Security headers: HSTS, CSP with nonce support, X-Frame-Options, Permissions-Policy
- File upload hardening: ZIP magic number validation, archive bomb detection, compression ratio limits
- License signature verification with HMAC-SHA256

### Deployment & Operations

- Installer scripts for Windows PowerShell and Linux/macOS Bash (`scripts/install.ps1`, `scripts/install.sh`)
- Docker multi-stage build with non-root user and security hardening
- Pre-flight startup validation (Python version, database, disk space, migrations)
- Diagnostics bundle generation for support tickets
- Privacy-first product telemetry (local-first, no PII)
- Release audit trail with version tracking
- License management with edition-based feature gating

### Frontend

- 52 page components with a consistent design system
- 30 reusable UI primitives
- Dark mode support
- Responsive design (desktop + mobile)
- TanStack React Query for data fetching
- Zustand for state management
- React Router v6 for navigation

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| Python | 3.11+ |
| RAM | 512 MB |
| Disk | 1 GB |
| OS | Windows 10+, Linux (Ubuntu 20.04+ or equivalent) |
| Docker | 24.0+ (optional) |

## Quick Start

See [QUICK_START.md](QUICK_START.md) and [INSTALL.md](INSTALL.md) for the
full, verified walkthrough (Docker, source install, and running the
frontend separately). Short version:

### Docker

```bash
docker build -t kingsec:2.0.0 .
docker run -d --name kingsec \
  --env-file .env \
  -p 8765:8765 \
  -v kingsec-data:/home/kingsec/.kingsec \
  kingsec:2.0.0
```

### From source

```bash
git clone <this-repository>
cd kingsec
pip install .
export KINGSEC_SECRETS__ENCRYPTION_KEY="<generate one — see INSTALL.md>"
kingsec-migrate
kingsec
```

---

## API Endpoints

- **Base URL:** `http://127.0.0.1:8765/api/v1`
- **Authentication:** JWT Bearer tokens
- **Documentation:** OpenAPI 3.1 (available at `/docs`)

---

## Breaking Changes

None. This is the first GA release.

## Deprecations

- `bootstrap/production.py` — use `bootstrap/composition.py` instead
- `create_schema()` — use `kingsec-migrate` (Alembic) instead

## Known Issues

- Alembic migration `aabbccddee00` has a duplicate index that may cause errors when upgrading from RC1 specifically. Fresh installs are unaffected (verified via a clean migration run against an empty database).
- Deployment page's "Check for Updates" is disabled by design: there is no mechanism yet to discover a target version to check against (the upgrade-plan endpoint works correctly but requires an explicit version). Not scheduled — flagging so it isn't lost.
- Assessments list search/status/sort controls exist in the frontend but can't be wired up: the backend only supports `limit`/`offset` on this endpoint (route, DTO, use case, and repository all the way down). Not scheduled — flagging so it isn't lost.
- No public endpoint exposes the running app version: Settings → About shows a hardcoded literal because the only real source (`/deployment/diagnostics`) requires admin, and the About page doesn't gate by role. Not scheduled — flagging so it isn't lost.

---

## Upgrade Path

### From RC1 (v2.0.0-rc1)

Reinstall from source and re-run migrations:

```bash
pip install --upgrade .
kingsec-migrate
```

### Fresh Install

Follow the Quick Start instructions above, or see [INSTALL.md](INSTALL.md).

---

## Support

- **Documentation:** see the `docs/` guides (INSTALL, QUICK_START, USER_GUIDE, ADMIN_GUIDE, SCANNER_GUIDE, TROUBLESHOOTING)
- **Issues / Security:** kingusecurity@gmail.com — see [SECURITY.md](../SECURITY.md) for the vulnerability-reporting process

---

## License

KingSec is proprietary software. All rights reserved.

Copyright (c) 2026 Abdul Mannan. See [LICENSE](../LICENSE).
