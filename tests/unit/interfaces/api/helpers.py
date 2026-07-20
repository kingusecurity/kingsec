"""Test helpers for legacy API route tests.

Provides a fake ``get_current_user`` dependency that bypasses real
authentication so that tests can exercise route logic without tokens.
"""

from __future__ import annotations

from datetime import UTC, datetime

from kingsec.application.ports import TokenClaims
from kingsec.domain import Role
from kingsec.interfaces.api.auth import CurrentUser


def fake_get_current_user() -> CurrentUser:
    """Return a synthetic admin user — used as a FastAPI ``Depends`` in tests."""
    return CurrentUser(
        user_id="test-user",
        username="test-admin",
        role=Role.ADMIN,
        claims=TokenClaims(
            user_id="test-user",
            username="test-admin",
            role="admin",
            token_type="access",
            jti="test-jti",
            issued_at=datetime.now(UTC),
            expires_at=datetime.now(UTC),
        ),
    )
