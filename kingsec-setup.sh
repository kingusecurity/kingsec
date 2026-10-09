#!/usr/bin/env bash
#
# KingSec one-shot setup.
#
# Creates a virtualenv, installs KingSec, applies the known binary-wheel
# fixes (cffi / pydantic-core), generates secrets into .env, provisions
# every wired scanner (wordlists for ffuf/gobuster, nuclei templates dir,
# ZAP lock cleanup, nikto clone), runs database migrations, and bootstraps
# the first admin account.
#
# Idempotent: safe to re-run — steps that are already done are skipped.
#
# Usage:
#   ./kingsec-setup.sh [--dev]      # --dev: editable install with dev tooling
#
# Environment overrides:
#   KINGSEC_VENV_DIR            venv location            (default: <repo>/.venv)
#   KINGSEC_STORAGE__DATA_DIR   data directory           (default: ~/.kingsec)
#   KINGSEC_BOOTSTRAP_USERNAME  admin username           (else prompted)
#   KINGSEC_BOOTSTRAP_PASSWORD  admin password           (else prompted securely)
#
# Works on Linux/macOS and on Windows under Git Bash.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

VENV_DIR="${KINGSEC_VENV_DIR:-$REPO_ROOT/.venv}"
export KINGSEC_STORAGE__DATA_DIR="${KINGSEC_STORAGE__DATA_DIR:-$HOME/.kingsec}"
ENV_FILE="$REPO_ROOT/.env"

# --- helpers ---------------------------------------------------------------
info() { printf '\033[0;34m>> %s\033[0m\n' "$1"; }
ok()   { printf '\033[0;32m   [OK] %s\033[0m\n' "$1"; }
warn() { printf '\033[0;33m   [WARN] %s\033[0m\n' "$1"; }
fail() { printf '\033[0;31m   [FAIL] %s\033[0m\n' "$1"; exit 1; }

# --- 0. Python version guard (fail fast on <3.11, loud warning on 3.14+) ----
info "Checking Python..."
if command -v python3 >/dev/null 2>&1; then PYBIN=python3
elif command -v python >/dev/null 2>&1; then PYBIN=python
else fail "No python found on PATH. Install Python 3.11–3.13 from https://www.python.org/downloads/"; fi

PYV="$($PYBIN -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
PY_MAJOR="${PYV%%.*}"; PY_MINOR="${PYV#*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    fail "Python 3.11+ required (found $PYV). KingSec is CI-tested on 3.11–3.13."
fi
ok "Found Python $PYV"
if [ "$PY_MINOR" -ge 14 ]; then
    warn "Python $PYV is newer than KingSec's CI-tested range (3.11–3.13); continuing, but expect rough edges."
fi

# --- 1. Virtual environment (idempotent) ------------------------------------
info "Virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    "$PYBIN" -m venv "$VENV_DIR"
    ok "Created $VENV_DIR"
else
    ok "Already exists at $VENV_DIR"
fi

# Resolve the venv interpreter on both layouts (bin/ on POSIX, Scripts/ on Windows).
if [ -x "$VENV_DIR/bin/python" ]; then VENV_PY="$VENV_DIR/bin/python"
elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then VENV_PY="$VENV_DIR/Scripts/python.exe"
else fail "Cannot find the venv interpreter under $VENV_DIR"; fi

# --- 2. Install KingSec -----------------------------------------------------
info "Installing KingSec..."
"$VENV_PY" -m pip install --quiet --upgrade pip
if [ "${1:-}" = "--dev" ]; then
    "$VENV_PY" -m pip install --quiet -e ".[dev]"
else
    "$VENV_PY" -m pip install --quiet .
fi
ok "Package installed"

# --- 3. Binary-wheel repair ---------------------------------------------------
# Preempts the "missing compiled binary" class of failures seen on real
# installs: a source-built cffi without _cffi_backend, or a pydantic-core
# newer than the installed pydantic's pin. Forces binary wheels only, and
# resolves pydantic-core's exact required version from installed metadata
# instead of hardcoding it (a hardcoded pin rots on the next bump).
info "Verifying compiled dependencies..."
"$VENV_PY" - <<'PYEOF'
import importlib.metadata as md
import subprocess
import sys

wanted = ["cffi", "cryptography"]
pin = None
try:
    for req in md.requires("pydantic") or []:
        candidate = req.split(";")[0].strip()  # drop environment markers
        if candidate.replace(" ", "").startswith("pydantic-core"):
            pin = candidate
            break
except md.PackageNotFoundError:
    pass
wanted.append(pin if pin else "pydantic-core")

subprocess.run(
    [sys.executable, "-m", "pip", "install", "--quiet",
     "--force-reinstall", "--only-binary", ":all:", *wanted],
    check=True,
)
print("binary-wheel repair applied for: " + ", ".join(wanted))
PYEOF
ok "Compiled dependencies verified"

# --- 4. Secrets (.env) — generate-if-missing, never print values ------------
info "Configuration..."
if [ ! -f "$ENV_FILE" ]; then
    cp .env.example "$ENV_FILE" 2>/dev/null || : > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    ok "Created $ENV_FILE"
else
    ok "$ENV_FILE already exists — only filling gaps"
fi

# Generate a missing secret and append it; existing values are never touched
# and values are never echoed to the terminal.
ensure_secret() {
    local var_name="$1" generator="$2"
    if grep -q "^${var_name}=" "$ENV_FILE" 2>/dev/null; then
        return 0
    fi
    local value
    value="$("$VENV_PY" -c "$generator")"
    printf '%s=%s\n' "$var_name" "$value" >> "$ENV_FILE"
    echo "generated ${var_name} (saved to .env, not shown)"
}

ensure_secret "KINGSEC_SECRETS__ENCRYPTION_KEY" \
    "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ensure_secret "KINGSEC_JWT__SECRET_KEY" \
    "import secrets; print(secrets.token_urlsafe(48))"
ensure_secret "KINGSEC_SECRETS__API_KEY_PEPPER" \
    "import secrets; print(secrets.token_urlsafe(48))"

# Set a plain (non-secret) config value only if it is not already present.
# Values are written quoted so paths containing spaces (e.g. Windows home
# directories like "C:\Users\Laptop Zone by JK") survive .env parsing.
ensure_env() {
    local var_name="$1" value="$2"
    if grep -q "^${var_name}=" "$ENV_FILE" 2>/dev/null; then
        return 0
    fi
    printf '%s="%s"\n' "$var_name" "$value" >> "$ENV_FILE"
    echo "configured ${var_name} (saved to .env)"
}

# --- 4b. Scanner prerequisites (wordlists, templates, auxiliary scanners) ---
# Wires every wired scanner KingSec ships so a fresh customer install can
# actually use them: ffuf/gobuster need a wordlist, nuclei wants an explicit
# templates dir, ZAP needs stale locks cleared, nikto needs Perl + a clone.
# Everything here is idempotent and never touches existing .env values.
info "Scanner prerequisites..."
for bin in nmap nuclei zap ffuf gobuster; do
    if command -v "$bin" >/dev/null 2>&1; then ok "$bin on PATH"; else warn "$bin NOT FOUND on PATH"; fi
done
if command -v perl >/dev/null 2>&1; then ok "perl ($(perl -v 2>/dev/null | sed -n '2p' | xargs))"; else warn "perl not found — nikto needs Strawberry Perl (strawberryperl.com)"; fi

WORDLIST_DIR="$HOME/wordlists"
mkdir -p "$WORDLIST_DIR"
if [ ! -s "$WORDLIST_DIR/common.txt" ]; then
    if curl -sL -o "$WORDLIST_DIR/common.txt" \
        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"; then
        ok "downloaded SecLists common.txt ($(wc -l < "$WORDLIST_DIR/common.txt" | xargs) entries)"
    else
        warn "wordlist download failed — check network, then re-run this script"
    fi
else
    ok "wordlist already present"
fi
if [ -s "$WORDLIST_DIR/common.txt" ]; then
    ensure_env "KINGSEC_FFUF__WORDLIST" "$WORDLIST_DIR/common.txt"
    ensure_env "KINGSEC_GOBUSTER__WORDLIST" "$WORDLIST_DIR/common.txt"
fi

if [ -d "$HOME/nuclei-templates" ]; then
    ensure_env "KINGSEC_SCANNER__TEMPLATES_DIR" "$HOME/nuclei-templates"
    ok "nuclei templates dir wired"
else
    warn "~/nuclei-templates not found — run 'nuclei' once to fetch templates, then re-run this script"
fi

# ZAP leaves a stale lock after a crash/kill; clear it (Windows/Git Bash only).
case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
        taskkill //F //IM java.exe 2>/dev/null || true
        rm -f "$HOME/ZAP/.lock" "$HOME/ZAP/zap.lock" 2>/dev/null || true
        ok "cleared stale ZAP locks"
        ;;
esac

if command -v perl >/dev/null 2>&1; then
    if [ ! -f "$HOME/nikto/program/nikto.pl" ]; then
        if git clone -q "https://github.com/sullo/nikto" "$HOME/nikto" 2>/dev/null; then
            ok "cloned nikto"
        else
            warn "nikto clone failed — check network/git, then re-run this script"
        fi
    else
        ok "nikto already present"
    fi
    if [ -f "$HOME/nikto/program/nikto.pl" ]; then
        ensure_env "KINGSEC_NIKTO__BINARY_PATH" "$HOME/nikto/program/nikto.pl"
    fi
    warn "nikto needs a Windows Defender exclusion for $HOME/nikto (Defender quarantines it on sight)"
else
    warn "skipping nikto: install Strawberry Perl first, then re-run this script"
fi

# --- 5. Database migrations ---------------------------------------------------
info "Database migrations..."
"$VENV_PY" -m kingsec._migrate
ok "Migrations applied"

# --- 6. Admin bootstrap (idempotent) ------------------------------------------
# kingsec-bootstrap refuses when an admin already exists — that refusal is
# the idempotency signal. Any other failure aborts the setup loudly.
info "Admin bootstrap..."
BOOT_USER="${KINGSEC_BOOTSTRAP_USERNAME:-}"
if [ -z "$BOOT_USER" ]; then
    read -r -p "Admin username: " BOOT_USER
fi
[ -n "$BOOT_USER" ] || fail "Username cannot be empty"
BOOT_PASS="${KINGSEC_BOOTSTRAP_PASSWORD:-}"
if [ -z "$BOOT_PASS" ]; then
    read -r -s -p "Admin password: " BOOT_PASS
    echo ""
fi
[ -n "$BOOT_PASS" ] || fail "Password cannot be empty"

BOOT_OUT=""
BOOT_RC=0
BOOT_OUT="$("$VENV_PY" -m kingsec._bootstrap --username "$BOOT_USER" --password "$BOOT_PASS" 2>&1)" || BOOT_RC=$?
if [ "$BOOT_RC" -eq 0 ]; then
    ok "Admin '$BOOT_USER' created"
elif echo "$BOOT_OUT" | grep -q "already exists"; then
    ok "An admin already exists — skipping"
else
    printf '%s\n' "$BOOT_OUT" >&2
    fail "Admin bootstrap failed (see above)"
fi
# Never keep the password in a shell variable longer than needed.
unset BOOT_PASS

# --- done ---------------------------------------------------------------------
cat <<EOF

=====================================
  KingSec setup complete
=====================================

  Backend:  ./kingsec-start.sh   (leave running; Ctrl+C to stop)
  Frontend: cd frontend && npm install && npm run dev
            then open http://localhost:5173

  API health: http://127.0.0.1:8765/api/v1/health
  Data dir:   $KINGSEC_STORAGE__DATA_DIR
  Config:     $ENV_FILE  (mode 600 — keep it private)

EOF
