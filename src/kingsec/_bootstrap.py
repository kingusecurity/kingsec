"""Command-line helper: create an admin user (recovery path).

Usage::

    python -m kingsec._bootstrap --username <name> --password <secret>
    kingsec-bootstrap --username <name> --password <secret>

Phase 3 (auth hardening): self-registration no longer grants ADMIN to
anyone, first user or not (see RegisterUser). This CLI is now the ONLY
way an initial administrator gets created - both for a fresh install and
for recovery after all admins are lost.

Refuses to run if an admin already exists (kept deliberately narrower
than "any user exists" - this tool's purpose is recovery, and a stricter
guard would refuse in the exact scenario it exists for: an admin lost
while ordinary user accounts survive).
Refuses to run if migrations have not been applied.
"""

from __future__ import annotations

import argparse
import importlib.resources
import subprocess  # nosec B404 — subprocess for alembic check
import sys
import uuid
from pathlib import Path

from kingsec import __version__
from kingsec.application import PasswordHasher
from kingsec.application.ports import AuditPublisher, UserRepository
from kingsec.application.use_cases.change_password import ChangePassword
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Role
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.user import PasswordValidationError, User


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

    # Phase 3: the account this CLI creates is the most powerful one in
    # the system - it must not be held to a weaker password standard than
    # a self-registered Viewer. Reuse ChangePassword._validate_password,
    # the canonical policy already reused by admin_users.py for the same
    # reason.
    try:
        ChangePassword._validate_password(password)
    except PasswordValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
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

        # Phase 3: the one deliberate, operator-invoked admin-creation
        # path previously had zero audit trail. Best-effort, matching the
        # existing _publish_audit pattern elsewhere (RegisterUser,
        # AssignRole) - a transient audit-backend failure must not stop
        # the one recovery tool that exists for a fully-locked-out
        # instance from finishing its job.
        try:
            audit: AuditPublisher = app.resolve(AuditPublisher)
            audit.record(
                AuditEntry(
                    action=AuditAction.ADMIN_BOOTSTRAPPED,
                    resource_type="user",
                    resource_id=admin.id,
                    success=True,
                    user_id=admin.id,
                    username=admin.username,
                    role=admin.role.label,
                )
            )
        except Exception as exc:
            print(f"WARNING: audit publish failed (best-effort): {exc}", file=sys.stderr)
    finally:
        app.stop()

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="kingsec-bootstrap", description="Create an admin user (recovery path)")
    parser.add_argument("--version", action="version", version=f"kingsec-bootstrap {__version__}")
    parser.add_argument("--username", required=True, help="Admin username")
    parser.add_argument("--password", required=True, help="Admin password")
    parser.add_argument("--email", default="", help="Admin email (optional)")
    args = parser.parse_args()
    return _bootstrap_admin(args.username, args.password, args.email)


if __name__ == "__main__":
    sys.exit(main())
