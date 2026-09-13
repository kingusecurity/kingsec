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


def run_migrations() -> int:
    """Apply all pending Alembic migrations using the packaged config."""
    parser = argparse.ArgumentParser(prog="kingsec-migrate", description="Apply pending Alembic migrations.")
    parser.add_argument("--version", action="version", version=f"kingsec-migrate {__version__}")
    parser.parse_args()

    config_path: str | Path = str(importlib.resources.files("kingsec.alembic").joinpath("alembic.ini"))
    alembic_dir = Path(config_path).parent
    return subprocess.call(  # nosec B603 — fixed argv from sys.executable, no shell=True, no user-controlled args
        [sys.executable, "-m", "alembic", "-c", str(config_path), "upgrade", "head"],
        cwd=str(alembic_dir),
    )


if __name__ == "__main__":
    sys.exit(run_migrations())
