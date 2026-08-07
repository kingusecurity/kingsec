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
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency resolution
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project metadata
COPY pyproject.toml README.md LICENSE ./

# Copy the application source
COPY src/ ./src/

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
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

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
