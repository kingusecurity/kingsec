# KingSec v1.0.0 — Production Release

**Version:** 1.0.0  
**Release Date:** 2026-07-20  
**Status:** Production Ready

## Overview

KingSec is a local-first, AI-augmented Attack Surface Management (ASM) and Vulnerability Management (VM) platform designed for small and mid-sized businesses. It runs on the user's machine, supports Bring-Your-Own-Key AI enrichment, and provides comprehensive security assessment capabilities through an extensible scanner orchestration framework.

## What's Included

### Core Platform
- **Authentication & Authorization**: JWT-based auth with access/refresh tokens, Argon2 password hashing, RBAC (ADMIN, ANALYST, VIEWER), session management, and MFA/TOTP support
- **Job System**: Persistent background job management with lifecycle tracking, retry support, and status reporting
- **Event System**: In-memory event bus for decoupled domain events
- **Report Generation**: Multi-format export (JSON, HTML, PDF, CSV, Markdown)

### Scanner Framework (10 pluggable scanners)
| Scanner | Focus | Module |
|---|---|---|
| Nuclei | Vulnerability scanning | 5.1 |
| Nmap | Network discovery & service detection | 5.3 |
| Nikto | Web server scanning | 5.4 |
| Trivy | Filesystem/container vulnerability scanning | 5.5 |
| OWASP ZAP | Web application security testing | 5.6 |
| Semgrep | Static code analysis | 5.7 |
| Amass | Subdomain enumeration | 5.8 |
| Gobuster | Directory enumeration | 5.9 |
| ffuf | Web fuzzing | 5.10 |

### AI Enrichment (BYO-Key)
- Automated finding enrichment via configurable AI providers
- Low-temperature deterministic analysis for security guidance
- Configurable retry and timeout settings

### API & Deployment
- FastAPI-based REST API with auto-generated OpenAPI documentation
- Docker multi-stage build for production deployment
- Docker Compose for orchestrated setups
- Alembic-based database migration management
- Structured logging (structlog) with JSON output support
- Comprehensive security headers and CORS configuration
- Rate limiting (per-IP token bucket)
- Health endpoint (unauthenticated)

## Installation

### Docker (recommended)

```bash
docker pull kingsec:1.0.0
docker run -d --name kingsec -p 8765:8765 -v kingsec-data:/home/kingsec/.kingsec kingsec:1.0.0
```

### Docker Compose

```bash
cp .env.example .env
docker compose up -d
```

### From source

```bash
pip install kingsec
alembic upgrade head
uvicorn kingsec.interfaces.api.app:create_app --host 127.0.0.1 --port 8765
```

## Upgrading from RC1

Run database migrations before starting the new version:

```bash
alembic upgrade head
```

## Known Issues

- Missing FK constraints on `JobRun` and `Artifact` models (planned for v1.1)
- No distributed job queue (single-node only; planned for v1.2)
- No built-in secrets rotation (manual key rotation in v1.1)

## Documentation

- Full README: [README.md](README.md)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: [SECURITY.md](SECURITY.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
