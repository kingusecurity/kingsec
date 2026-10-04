"""Outbound port: persists and retrieves :class:`AuthorizationGrant` aggregates.

Phase 4 (authorization scope enforcement). Deliberately plain CRUD plus one
targeted finder (``find_active``) - the actual scope-matching algorithm
(covers_target()/satisfies_tier(), and the find_covering() that will sit on
top of them) is pure domain/application logic with no persistence
dependency, so it is never pushed down into this port or into SQL. This
mirrors AssessmentRepository/SessionRepository: the repository's job is
storage, not business rules.
"""

from __future__ import annotations

import builtins
from abc import ABC, abstractmethod
from datetime import datetime

from kingsec.domain import AuthorizationGrant
from kingsec.domain.identifiers import AuthorizationGrantId


class AuthorizationGrantRepository(ABC):
    """Persists and retrieves :class:`AuthorizationGrant` aggregates."""

    @abstractmethod
    def save(self, grant: AuthorizationGrant) -> None:
        """Insert or update the given grant (upsert semantics)."""

    @abstractmethod
    def get(self, grant_id: AuthorizationGrantId) -> AuthorizationGrant:
        """Return the grant for the id.

        Raises:
            AuthorizationGrantNotFoundError: If no row exists for this id.
        """

    @abstractmethod
    def list(self, *, limit: int = 50, offset: int = 0) -> builtins.list[AuthorizationGrant]:
        """Return one page of grants ordered by created (valid_from) DESC."""

    @abstractmethod
    def find_active(self, at: datetime) -> builtins.list[AuthorizationGrant]:
        """Return every grant whose window covers *at* and is not revoked
        before it - i.e. every grant for which ``grant.is_active(at)`` is
        True.

        The candidate set an enforcement check narrows via
        covers_target()/satisfies_tier() (Phase 4 tasks #626/#627) - kept
        as a plain time-window filter here, never a target- or
        tier-aware query, since that matching logic belongs to the pure
        domain functions in authorization_grant.py, not to this port or
        to SQL.
        """

    @abstractmethod
    def revoke(self, grant_id: AuthorizationGrantId, revoked_at: datetime) -> None:
        """Mark the grant revoked as of *revoked_at*.

        Raises:
            AuthorizationGrantNotFoundError: If no row exists for this id.
        """
