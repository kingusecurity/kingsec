"""CreateAuthorizationGrant / RevokeAuthorizationGrant use cases (Phase 4).

Completes "all four audit actions": AUTHORIZATION_GRANT_CREATED and
AUTHORIZATION_GRANT_REVOKED need a real creation/revocation path to fire
from, the same way SCOPE_CHECK_REFUSED/SCOPE_CHECK_OVERRIDDEN needed
CreateAssessment's own enforcement wiring (test_create_assessment.py).
"""

from __future__ import annotations

import pytest
from tests.unit.application.conftest import InMemoryAuthorizationGrantRepository

from kingsec.application.dto import (
    CreateAuthorizationGrantRequest,
    RevokeAuthorizationGrantRequest,
)
from kingsec.application.errors import AuthorizationGrantNotFoundError, InputValidationError
from kingsec.application.ports import AuditPublisher
from kingsec.application.use_cases.create_authorization_grant import CreateAuthorizationGrant
from kingsec.application.use_cases.revoke_authorization_grant import RevokeAuthorizationGrant
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.identifiers import AuthorizationGrantId


class _RecordingAuditPublisher(AuditPublisher):
    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


def _create_request(**overrides: str) -> CreateAuthorizationGrantRequest:
    data = {
        "authorized_by": "ciso@example.com",
        "authorizing_organization": "Example Corp",
        "target_specification_type": "ip_address",
        "target_specification_value": "203.0.113.5",
        "valid_from": "2026-01-01T00:00:00+00:00",
        "valid_until": "2026-02-01T00:00:00+00:00",
        "created_by": "admin@kingusecurity.com",
    }
    data.update(overrides)
    return CreateAuthorizationGrantRequest(**data)  # type: ignore[arg-type]


class TestCreateAuthorizationGrant:
    def test_creates_and_persists_a_grant(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        response = CreateAuthorizationGrant(grants).execute(_create_request())

        assert response.target_specification_type == "ip_address"
        assert response.target_specification_value == "203.0.113.5"
        stored = grants.get(AuthorizationGrantId(response.grant_id))
        assert stored.authorized_by == "ciso@example.com"
        assert stored.authorizing_organization == "Example Corp"

    def test_publishes_authorization_grant_created(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        audit = _RecordingAuditPublisher()
        CreateAuthorizationGrant(grants, audit=audit).execute(_create_request())

        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry.action == AuditAction.AUTHORIZATION_GRANT_CREATED
        assert entry.success is True
        assert entry.metadata["target_specification_value"] == "203.0.113.5"

    def test_rejects_invalid_target_specification_type(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        with pytest.raises(InputValidationError):
            CreateAuthorizationGrant(grants).execute(_create_request(target_specification_type="banana"))

    def test_rejects_malformed_target_specification_value(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        with pytest.raises(InputValidationError):
            CreateAuthorizationGrant(grants).execute(
                _create_request(target_specification_type="ip_address", target_specification_value="not-an-ip")
            )

    def test_rejects_naive_valid_from(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        with pytest.raises(InputValidationError):
            CreateAuthorizationGrant(grants).execute(_create_request(valid_from="2026-01-01T00:00:00"))

    def test_rejects_malformed_valid_from(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        with pytest.raises(InputValidationError):
            CreateAuthorizationGrant(grants).execute(_create_request(valid_from="not-a-date"))

    def test_rejects_valid_until_not_after_valid_from(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        with pytest.raises(InputValidationError):
            CreateAuthorizationGrant(grants).execute(
                _create_request(valid_from="2026-02-01T00:00:00+00:00", valid_until="2026-01-01T00:00:00+00:00")
            )


class TestRevokeAuthorizationGrant:
    def _existing_grant_id(self, grants: InMemoryAuthorizationGrantRepository) -> str:
        return CreateAuthorizationGrant(grants).execute(_create_request()).grant_id

    def test_revokes_an_existing_grant(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        grant_id = self._existing_grant_id(grants)

        response = RevokeAuthorizationGrant(grants).execute(
            RevokeAuthorizationGrantRequest(grant_id=grant_id, revoked_by="admin@kingusecurity.com")
        )

        assert response.grant_id == grant_id
        stored = grants.get(AuthorizationGrantId(grant_id))
        assert stored.revoked_at is not None

    def test_publishes_authorization_grant_revoked(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        grant_id = self._existing_grant_id(grants)
        audit = _RecordingAuditPublisher()

        RevokeAuthorizationGrant(grants, audit=audit).execute(
            RevokeAuthorizationGrantRequest(grant_id=grant_id, revoked_by="admin@kingusecurity.com")
        )

        assert len(audit.entries) == 1
        entry = audit.entries[0]
        assert entry.action == AuditAction.AUTHORIZATION_GRANT_REVOKED
        assert entry.success is True
        assert entry.resource_id == grant_id

    def test_raises_not_found_for_unknown_grant_id(self) -> None:
        grants = InMemoryAuthorizationGrantRepository()
        with pytest.raises(AuthorizationGrantNotFoundError):
            RevokeAuthorizationGrant(grants).execute(
                RevokeAuthorizationGrantRequest(grant_id="agrt-does-not-exist", revoked_by="admin@kingusecurity.com")
            )

    def test_revoked_grant_is_no_longer_active(self) -> None:
        from datetime import UTC, datetime

        grants = InMemoryAuthorizationGrantRepository()
        grant_id = self._existing_grant_id(grants)

        RevokeAuthorizationGrant(grants).execute(
            RevokeAuthorizationGrantRequest(grant_id=grant_id, revoked_by="admin@kingusecurity.com")
        )

        stored = grants.get(AuthorizationGrantId(grant_id))
        assert stored.is_active(datetime.now(UTC)) is False
