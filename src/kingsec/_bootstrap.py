"""Command-line helper: create an admin user (recovery path).

Usage::

    python -m kingsec._bootstrap --username <name> --password <secret>
    kingsec-bootstrap --username <name> --password <secret>

The first administrator is created automatically on first registration.
This CLI exists for recovery scenarios (e.g. after all admins are lost).

Refuses to run if any admin already exists.
Refuses to run if migrations have not been applied.
"""

from __future__ import annotations

import argparse
import importlib.resources
import subprocess  # nosec B404 — subprocess for alembic check
import sys
import uuid
from pathlib import Path

from kingsec.application import PasswordHasher
from kingsec.application.ports import UserRepository
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Role
from kingsec.domain.user import User


def _migrations_applied() -> bool:
    config_path: str | Path = str(importlib.resources.files("kingsec.alembic").joinpath("alembic.ini"))
    alembic_dir = Path(config_path).parent
    result = subprocess.call(  # nosec B603 — fixed argv, no shell
        [sys.executable, "-m", "alembic", "-c", str(config_path), "check"],
        cwd=str(alembic_dir),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result == 0


def _bootstrap_admin(username: str, password: str, email: str = "") -> int:
    if not _migrations_applied():
        print("ERROR: migrations not applied; run 'kingsec-migrate' first", file=sys.stderr)
        return 1

    app = create_wired_application(validate_migrations=False)
    app.start()

    try:
        users: UserRepository = app.resolve(UserRepository)
        if users.count_by_role(Role.ADMIN) > 0:
            print("ERROR: an admin user already exists", file=sys.stderr)
            return 1

        hasher: PasswordHasher = app.resolve(PasswordHasher)

        admin = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email or f"{username}@kingsec.local",
            password_hash=hasher.hash(password),
            role=Role.ADMIN,
        )
        users.save(admin)
        print(f"Admin user '{username}' created successfully (id={admin.id})")
    finally:
        app.stop()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an admin user (recovery path)")
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--email", default="", help="Admin email (optional)")
    args = parser.parse_args()
    return _bootstrap_admin(args.username, args.password, args.email)


if __name__ == "__main__":
    sys.exit(main())
