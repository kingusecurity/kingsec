"""Command-line helper: run Alembic migrations using the packaged config.

Usage::

    python -m kingsec._migrate
    kingsec-migrate          # if installed via pip
    kingsec-migrate --help
    kingsec-migrate --version
"""

from __future__ import annotations

import argparse
import importlib.resources
import subprocess  # nosec B404 — Alembic migration subprocess uses sys.executable, no shell, fixed argv
import sys
from pathlib import Path

from kingsec import __version__
from kingsec._python_guard import ensure_supported_python


def run_migrations() -> int:
    """Apply all pending Alembic migrations using the packaged config."""
    ensure_supported_python()

    parser = argparse.ArgumentParser(prog="kingsec-migrate", description="Apply pending Alembic migrations.")
    parser.add_argument("--version", action="version", version=f"kingsec-migrate {__version__}")
    parser.parse_args()

    # The data-dir notice is printed by the subprocess itself (env.py's
    # _resolve_database_url(), which already resolves settings there) and
    # inherited onto this process's own stderr - not resolved again here.
    # kingsec._migrate is imported by an inbound adapter
    # (deployment_routes.py), so it must not import kingsec.infrastructure
    # itself (hexagonal layering contract) - env.py is a separate
    # subprocess, outside that import graph entirely.
    config_path: str | Path = str(importlib.resources.files("kingsec.alembic").joinpath("alembic.ini"))
    alembic_dir = Path(config_path).parent
    return subprocess.call(  # nosec B603 — fixed argv from sys.executable, no shell=True, no user-controlled args
        [sys.executable, "-m", "alembic", "-c", str(config_path), "upgrade", "head"],
        cwd=str(alembic_dir),
    )


if __name__ == "__main__":
    sys.exit(run_migrations())
