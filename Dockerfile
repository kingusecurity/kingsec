# =============================================================================
# KingSec — Multi-stage Docker Build
# =============================================================================
# Stage 1: Frontend build (produces frontend/dist, bundled into the wheel
# by the next stage - the running backend serves it same-origin, see
# adapters/inbound/web/spa.py)
FROM node:20-slim AS frontend-builder

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# =============================================================================
# Stage 2: Build (build the wheel from source)
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    git \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Extract exactly the committed source tree via `git archive`, not a raw
# filesystem copy. A plain `COPY src/ ./src/` brings in whatever is
# physically sitting in the build host's working tree, tracked or not -
# this is how untracked Alembic autogenerate artifacts
# (src/kingsec/alembic/versions/*__no_changes.py, Phase 15/16) ended up
# baked into every wheel this project built. `git archive HEAD` reads only
# what HEAD's commit actually contains, so the shipped artifact depends on
# what is committed, never on what happens to be lying around. .git is
# read here only - never copied into the runtime stage below.
COPY .git ./.git
RUN git archive HEAD | tar -x && rm -rf .git

# Bundle the frontend build into the package before packaging - artifacts
# in pyproject.toml's wheel target picks this up even though static/ is
# gitignored (it's generated, not committed).
COPY --from=frontend-builder /frontend/dist/ ./src/kingsec/adapters/inbound/web/static/

# Build the wheel
RUN uv pip install --system build && \
    python -m build --wheel --outdir=/build/dist

# =============================================================================
# Stage 3: Runtime (minimal image)
FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -r kingsec && useradd -r -g kingsec -d /home/kingsec -s /sbin/nologin kingsec && \
    mkdir -p /home/kingsec && chown kingsec:kingsec /home/kingsec

# Runtime system libraries (WeasyPrint dependencies)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Copy the wheel from builder
COPY --from=builder /build/dist/*.whl /tmp/
# Upgrade pip before installing the wheel - the python:3.12-slim base image's
# baked-in pip has been below the fixed version for several known CVEs
# (PYSEC-2026-196, -1795, -1796, -2875, -2876); pip is a build-time tool
# never imported or executed by the running application (Phase 11), but its
# version is still what ends up baked into the shipped image's site-packages.
RUN pip install --no-cache-dir --upgrade "pip>=26.1.2" && \
    pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Create data directory
RUN mkdir -p /home/kingsec/.kingsec && chown kingsec:kingsec /home/kingsec/.kingsec

WORKDIR /home/kingsec
USER kingsec

# Expose the default API port
EXPOSE 8765

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/v1/health')"

# Default command: run migrations and start the server via python -m kingsec
CMD ["sh", "-c", "kingsec-migrate && python -m kingsec"]
