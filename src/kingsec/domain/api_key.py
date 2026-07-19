"""API Key domain entity — pure business model for enterprise API key authentication.

API keys are long-lived credentials used by CI/CD pipelines, automation scripts,
integrations, and service-to-service communication. Unlike JWT tokens, API keys:

    - Have no expiration (they are revoked explicitly).
    - Are shown in plaintext only once, at creation time.
    - Are stored as hashes — the plaintext key is never persisted.
    - Carry metadata (name, scope, last used timestamp) for auditing.
    - Are owned by a user; admins can manage any key, users manage their own.

Security model:
    - The plaintext key is generated server-side using a cryptographically
      random source (``secrets.token_urlsafe``).
    - Only the hash is stored; the plaintext is returned once in the creation
      response and never recoverable afterward.
    - Key status (active / revoked) controls whether the key is accepted.
    - Scopes restrict what the key can do (not tied to user roles).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class ApiKeyStatus(Enum):
    """Lifecycle state of an API key."""

    ACTIVE = "active"
    REVOKED = "revoked"

    @property
    def is_active(self) -> bool:
        return self is ApiKeyStatus.ACTIVE


class ApiKeyScope(Enum):
    """Operational scope of an API key.

    Scopes allow fine-grained control independent of the owning user's role:
        - READ_ONLY: can list assessments, view reports, read health.
        - FULL_ACCESS: can create assessments, start scans, generate reports.
    """

    READ_ONLY = "read_only"
    FULL_ACCESS = "full_access"


@dataclass
class ApiKey:
    """An API key used for machine-to-machine authentication.

    Attributes:
        id: Unique identifier (UUID string).
        user_id: The owning user's ID.
        name: A human-readable label for the key (e.g. "CI/CD Pipeline").
        key_hash: The hashed value of the plaintext key.
        scope: Operational scope of the key.
        status: Current lifecycle state (active or revoked).
        last_used_at: Timestamp of the most recent successful use (UTC).
        created_at: Key creation timestamp (UTC).
    """

    id: str
    user_id: str
    name: str
    key_hash: str
    scope: ApiKeyScope
    status: ApiKeyStatus = ApiKeyStatus.ACTIVE
    last_used_at: datetime | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def revoke(self) -> None:
        """Revoke this API key. Revoked keys cannot be reactivated."""
        self.status = ApiKeyStatus.REVOKED

    def record_usage(self) -> None:
        """Record a successful authentication with this key."""
        self.last_used_at = datetime.now(UTC)
