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
import getpass
import importlib.resources
import sys
import uuid

from kingsec import __version__
from kingsec._cli_messages import migrations_not_applied_message
from kingsec._data_dir_notice import announce_data_dir
from kingsec.application import PasswordHasher
from kingsec.application.ports import AuditPublisher, UserRepository
from kingsec.application.use_cases.change_password import ChangePassword
from kingsec.bootstrap.composition import create_wired_application
from kingsec.domain import Role
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.user import PasswordValidationError, User
from kingsec.infrastructure.config import Settings, load_settings
from kingsec.infrastructure.persistence import create_database_engine


def _migration_chain_status(settings: Settings) -> tuple[bool, str]:
    """Check only whether the Alembic migration chain is at head.

    Deliberately narrower than `alembic check`: that command ALSO runs an
    autogenerate schema diff against the live ORM models, which fails on
    any unrelated schema drift (e.g. a table removed from models.py with
    no DROP migration) even when the migration chain itself is genuinely
    fully applied. That conflation is exactly what made this check return
    a false "not applied" against a real, fully-migrated database - see
    docs/STATUS.md.

    Reuses Alembic's own ``ScriptDirectory``/``MigrationContext`` - the
    same objects `alembic current` itself is built on - rather than adding
    a fourth, bespoke notion of "is this migrated" alongside the three
    that already disagreed.

    Returns:
        ``(at_head, detail)`` — ``detail`` names the current and head
        revisions, for an operator-actionable message when it is False.
    """
    from alembic.config import Config
    from alembic.runtime.migration import MigrationContext
    from alembic.script import ScriptDirectory

    config_path = str(importlib.resources.files("kingsec.alembic").joinpath("alembic.ini"))
    config = Config(config_path)
    script = ScriptDirectory.from_config(config)
    script_heads = set(script.get_heads())

    engine = create_database_engine(settings=settings)
    try:
        with engine.connect() as conn:
            context = MigrationContext.configure(conn)
            current_heads = set(context.get_current_heads())
    finally:
        engine.dispose()

    at_head = current_heads == script_heads
    detail = f"current={sorted(current_heads) or ['<none>']} head={sorted(script_heads)}"
    return at_head, detail


def _bootstrap_admin(username: str, password: str, email: str = "") -> int:
    settings = load_settings()
    announce_data_dir(settings)

    at_head, detail = _migration_chain_status(settings)
    if not at_head:
        print(f"ERROR: {migrations_not_applied_message(detail)}", file=sys.stderr)
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
    parser.add_argument(
        "--password",
        help="Admin password (omit to enter it securely at an interactive prompt)",
    )
    parser.add_argument("--email", default="", help="Admin email (optional)")
    args = parser.parse_args()

    password = args.password
    if password is None:
        if not sys.stdin.isatty():
            parser.error("--password is required when no interactive terminal is available")
        password = getpass.getpass("Admin password: ")
        confirmation = getpass.getpass("Confirm admin password: ")
        if password != confirmation:
            print("ERROR: passwords do not match", file=sys.stderr)
            return 1

    return _bootstrap_admin(args.username, password, args.email)


if __name__ == "__main__":
    sys.exit(main())
