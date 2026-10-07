#!/usr/bin/env bash
#
# Start the KingSec backend using the venv prepared by kingsec-setup.sh.
#
# Usage: ./kingsec-start.sh [--host HOST] [--port PORT]
#        (extra arguments are passed through to `kingsec`)
#
# Runs from the repo root so the settings layer auto-loads ./.env.
# Leave running; stop with Ctrl+C.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

VENV_DIR="${KINGSEC_VENV_DIR:-$REPO_ROOT/.venv}"
export KINGSEC_STORAGE__DATA_DIR="${KINGSEC_STORAGE__DATA_DIR:-$HOME/.kingsec}"

if [ -x "$VENV_DIR/bin/python" ]; then VENV_PY="$VENV_DIR/bin/python"
elif [ -x "$VENV_DIR/Scripts/python.exe" ]; then VENV_PY="$VENV_DIR/Scripts/python.exe"
else
    printf '\033[0;31m   [FAIL] No venv at %s — run ./kingsec-setup.sh first\033[0m\n' "$VENV_DIR" >&2
    exit 1
fi

exec "$VENV_PY" -m kingsec "$@"
