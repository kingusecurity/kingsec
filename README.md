# KingSec

Local-first, AI-augmented **Attack Surface Management (ASM)** and **Vulnerability Management (VM)** for small and mid-sized businesses.

> **Status:** Module 1 - Project Foundation. This repository is a scaffold. It contains the production project structure, tooling, and conventions; it does **not** yet contain application logic.

## Principles baked into the foundation
- **Local-first & private.** Runs on the user's machine; the web server binds to `127.0.0.1` by default.
- **Bring-your-own-AI-key.** AI credentials are user-supplied and never leave the machine or the repository.
- **Honest by design.** No fake progress, no fear-selling, no paywalled critical findings.
- **Safe by default.** An authorization gate guards any active scanning and is enabled by default.

## Architecture
Hexagonal (ports & adapters). The pure core (`domain`, `application`) is delivery-agnostic; everything external plugs in through ports. See [`docs/FOUNDATION.md`](docs/FOUNDATION.md) for the full blueprint and [`docs/adr/`](docs/adr/) for recorded decisions.

## Quick start (development)
```bash
# 1. Install uv (https://docs.astral.sh/uv/) - the recommended environment manager
# 2. Create the environment and install runtime + dev dependencies, install hooks
make install
# 3. Run every quality gate (lint, types, architecture, security, tests)
make check
```
Run `make help` to list all developer tasks.

## Layout
See [`docs/FOUNDATION.md`](docs/FOUNDATION.md) sections 2-3 for the full folder tree and the rationale for each directory.

## Security
Found a vulnerability? Please read [`SECURITY.md`](SECURITY.md).

## License
Proprietary. All rights reserved. See [`LICENSE`](LICENSE).
