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

- **SSO Integration** — SAML/OIDC identity provider support
- **Role-Based Access Control** — Viewer, Analyst, and Admin roles with granular permissions
- **Audit Trail** — Complete activity logging with export capabilities
- **Plugin SDK** — Extensible plugin system with sandboxed execution
- **Distributed Workers** — Multi-node task processing with job queuing
- **Backup & Restore** — Automated backup with point-in-time recovery

### Security Hardening (Phases 29–30)

- SSRF protection on all outbound HTTP clients
- Plugin sandboxing with filesystem isolation, execution timeout, and memory limits
- Account lockout with progressive delays (60s → 120s → 300s → 600s)
- Input validation against SQL injection, XSS, and path traversal
- Security headers: HSTS, CSP with nonce support, X-Frame-Options, Permissions-Policy
- File upload hardening: ZIP magic number validation, archive bomb detection, compression ratio limits
- License signature verification with HMAC-SHA256

### Deployment & Operations (Phases 31–32)

- One-click installer scripts (Windows PowerShell, Linux/macOS Bash)
- Docker multi-stage build with non-root user and security hardening
- Pre-flight startup validation (Python version, database, disk space, migrations)
- Diagnostics bundle generation for support tickets
- Privacy-first product telemetry (local-first, no PII)
- Release audit trail with version tracking
- License management with edition-based feature gating

### Frontend

- 52 page components with consistent design system
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
| OS | Windows 10+, macOS 12+, Ubuntu 20.04+ |
| Docker | 24.0+ (optional) |

## Quick Start

### Docker (Recommended)

```bash
docker build -t kingsec:2.0.0 .
docker run -d --name kingsec \
  --env-file .env \
  -p 8765:8765 \
  -v kingsec-data:/home/kingsec/.kingsec \
  kingsec:2.0.0
```

### Native Install

```bash
# Windows
powershell -ExecutionPolicy Bypass -File scripts/install.ps1

# Linux/macOS
curl -sSL https://raw.githubusercontent.com/kingsec/main/scripts/install.sh | bash
```

### Development

```bash
pip install -e ".[dev]"
kingsec-migrate
python -m kingsec
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

- `bootstrap/production.py` — Use `bootstrap/composition.py` instead
- `create_schema()` — Use `kingsec-migrate` (Alembic) instead

## Known Issues

- Alembic migration `aabbccddee00` has a duplicate index that may cause errors on upgrade from RC1. Fresh installs are unaffected.
- Pre-existing TypeScript errors in `QueuePage`, `WorkersPage`, `ThreatTimelinePage`, and `ThreatIntelligenceDashboard` (cosmetic, not functional)

---

## Upgrade Path

### From RC1 (v2.0.0-rc1)

```bash
pip install kingsec==2.0.0
kingsec-migrate upgrade head
```

### Fresh Install

Follow the Quick Start instructions above.

---

## Support

- **Documentation:** See the `docs/` directory
- **Issues:** Report at https://github.com/kingusecurity/kingsec/issues
- **Security:** Report vulnerabilities to security@kingsec.dev

---

## License

KingSec is proprietary software. All rights reserved.

Copyright (c) 2026 KingSec. Unauthorized copying, modification, or distribution of this software is strictly prohibited.
