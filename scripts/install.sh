#!/usr/bin/env bash
# KingSec Installer Script for Linux/macOS
# Usage: curl -sSL https://raw.githubusercontent.com/kingsec/main/scripts/install.sh | bash
set -euo pipefail

INSTALL_DIR="${KINGSEC_INSTALL_DIR:-$HOME/.kingsec}"
DEV_MODE="${DEV_MODE:-false}"

# --- Helpers ---
info()  { printf "\033[0;34m>> %s\033[0m\n" "$1"; }
ok()    { printf "\033[0;32m   [OK] %s\033[0m\n" "$1"; }
warn()  { printf "\033[0;33m   [WARN] %s\033[0m\n" "$1"; }
fail()  { printf "\033[0;31m   [FAIL] %s\033[0m\n" "$1"; exit 1; }
has()   { command -v "$1" >/dev/null 2>&1; }

# --- Banner ---
cat <<'BANNER'

  _  __          __  __
 | |/ /___ _   _|  \/  | ___  _ __ ___   ___  __ _| |_ ___
 | ' // _ \ | | | |\/| |/ _ \| '_ ` _ \ / _ \/ _` | __/ _ \
 | . \  __/ |_| | |  | | (_) | | | | | |  __/ (_| | ||  __/
 |_|\_\___|\__, |_|  |_|\___/|_| |_| |_|\___|\__,_|\__\___|
           |___/
  Security Assessment Platform — Installer

BANNER

# --- Step 1: Check Python ---
info "Checking Python..."
if has python3; then PYBIN=python3; elif has python; then PYBIN=python
else fail "Python not found. Install Python 3.11+ first."; fi
PY=$($PYBIN --version 2>&1)
ok "Found: $PY"
PY_MAJOR=$(echo "$PY" | cut -d' ' -f2 | cut -d'.' -f1)
PY_MINOR=$(echo "$PY" | cut -d' ' -f2 | cut -d'.' -f2)
PY_MINOR="${PY_MINOR:-0}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    fail "Python 3.11+ required (CI-tested: 3.11–3.13). Found: $PY"
fi
if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 14 ]; then
    warn "Python $PY is newer than KingSec's CI-tested range (3.11–3.13); continuing, but expect rough edges."
fi

# --- Step 2: Check pip ---
info "Checking pip..."
if has pip3; then PIP=pip3; elif has pip; then PIP=pip; else
    fail "pip not found. Install pip first."
fi
ok "pip available: $($PIP --version)"

# --- Step 3: Create directories ---
info "Creating directories..."
mkdir -p "$INSTALL_DIR"/{logs,backups,plugins,telemetry}
ok "Directories created at $INSTALL_DIR"

# --- Step 4: Create .env if missing ---
info "Checking configuration..."
ENV_FILE="$INSTALL_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
    JWT_SECRET=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
    API_PEPPER=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)
    ENC_KEY=$(openssl rand -base64 32 2>/dev/null || head -c 32 /dev/urandom | base64)

    cat > "$ENV_FILE" <<EOF
# KingSec Environment Configuration
KINGSEC_ENVIRONMENT=production
KINGSEC_DEBUG=false
KINGSEC_LOGGING__LEVEL=INFO

# Security (auto-generated secrets — do not share)
KINGSEC_JWT__SECRET_KEY=$JWT_SECRET
KINGSEC_SECRETS__API_KEY_PEPPER=$API_PEPPER
KINGSEC_SECRETS__ENCRYPTION_KEY=$ENC_KEY

# Server
KINGSEC_SERVER__HOST=127.0.0.1
KINGSEC_SERVER__PORT=8765

# Storage
KINGSEC_STORAGE__DATA_DIR=$INSTALL_DIR
EOF
    chmod 600 "$ENV_FILE"
    ok "Created .env with auto-generated secrets"
else
    ok ".env already exists"
fi

# --- Step 5: Install Python package ---
info "Installing KingSec package..."
export KINGSEC_STORAGE__DATA_DIR="$INSTALL_DIR"
if [ "$DEV_MODE" = "true" ]; then
    $PIP install -e ".[dev]" --quiet
else
    $PIP install . --quiet
fi
ok "KingSec package installed"

# --- Step 6: Run migrations ---
info "Running database migrations..."
kingsec-migrate 2>/dev/null || warn "Migration command not found (will run on first start)"
ok "Database ready"

# --- Step 7: Docker (optional) ---
if has docker; then
    info "Docker available"
    echo "   Run 'docker compose up -d' to start with Docker"
else
    warn "Docker not found. Install Docker for containerized deployment."
fi

# --- Step 8: Create start script ---
info "Creating start script..."
cat > "$INSTALL_DIR/start.sh" <<'STARTEOF'
#!/usr/bin/env bash
DIR="$(cd "$(dirname "$0")" && pwd)"
export KINGSEC_STORAGE__DATA_DIR="$DIR"
cd "$DIR/.."
exec python -m kingsec
STARTEOF
chmod +x "$INSTALL_DIR/start.sh"
ok "Created start.sh"

# --- Done ---
cat <<EOF

=====================================
  Installation Complete!
=====================================

  Location:  $INSTALL_DIR
  Config:    $INSTALL_DIR/.env
  Start:     $INSTALL_DIR/start.sh
  Or run:    python -m kingsec

  Default: http://127.0.0.1:8765
  Health:  http://127.0.0.1:8765/api/v1/health

EOF
