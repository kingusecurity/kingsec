"""Unit tests for LicenseActivationService and LicenseValidatorImpl.

Real signed keys need a real Ed25519 keypair - never the actual shipped
signing key (that private key intentionally isn't available to test code,
same as it isn't available to the running application). Tests that need a
"genuinely signed" key generate an ephemeral test keypair and monkeypatch
the module's embedded public key to match it for the duration of the test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kingsec.application.ports.outbound.license_repository import LicenseRepository
from kingsec.application.services import licensing as licensing_module
from kingsec.application.services.license_key_codec import (
    InvalidLicenseKeyError,
    encode_license_key,
)
from kingsec.application.services.licensing import (
    LicenseActivationService,
    LicenseGate,
    LicenseValidatorImpl,
)
from kingsec.domain.license import License, LicenseEdition, LicenseId, LicenseStatus


class _InMemoryLicenseRepository(LicenseRepository):
    def __init__(self) -> None:
        self._by_id: dict[str, License] = {}

    def save(self, license: License) -> None:
        self._by_id[str(license.id)] = license

    def find_active(self) -> License | None:
        for lic in self._by_id.values():
            if lic.status in (LicenseStatus.ACTIVE, LicenseStatus.GRACE_PERIOD):
                return lic
        return None

    def find_by_key(self, license_key: str) -> License | None:
        for lic in self._by_id.values():
            if lic.license_key == license_key:
                return lic
        return None

    def list_all(self) -> list[License]:
        return list(self._by_id.values())

    def delete(self, license_id: str) -> None:
        self._by_id.pop(license_id, None)

    def exists(self) -> bool:
        return bool(self._by_id)


class _RecordingAudit:
    def __init__(self) -> None:
        self.entries: list[object] = []

    def record(self, entry: object) -> None:
        self.entries.append(entry)


def _signed_key(monkeypatch: pytest.MonkeyPatch, **payload_overrides: object) -> str:
    """Generate an ephemeral keypair, monkeypatch the module's embedded
    public key to match it, and return a real, verifiably-signed key."""
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    monkeypatch.setattr(licensing_module, "LICENSE_SIGNING_PUBLIC_KEY", public_key_bytes)

    payload: dict[str, object] = {
        "license_id": "lic-abc123",
        "edition": "professional",
        "issued_to": "Acme Corp",
        "email": "admin@acme.com",
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": "",
        "max_users": None,
        "max_organizations": None,
        "features": [],
    }
    payload.update(payload_overrides)
    return encode_license_key(payload, private_key)


ActivationFixture = tuple[LicenseActivationService, _InMemoryLicenseRepository, _RecordingAudit]


@pytest.fixture
def activation_service() -> ActivationFixture:
    repo = _InMemoryLicenseRepository()
    validator = LicenseValidatorImpl(repo)
    gate = LicenseGate(repo, validator)
    audit = _RecordingAudit()
    service = LicenseActivationService(repo, validator, gate, audit)
    return service, repo, audit


class TestActivateRejectsInvalidInput:
    def test_arbitrary_string_is_rejected(self, activation_service: ActivationFixture) -> None:
        service, _, _ = activation_service
        with pytest.raises(InvalidLicenseKeyError):
            service.activate("KS-BOGUS-KEY-0000")

    def test_empty_string_is_rejected(self, activation_service: ActivationFixture) -> None:
        service, _, _ = activation_service
        with pytest.raises(InvalidLicenseKeyError):
            service.activate("")

    def test_key_signed_by_a_different_key_is_rejected(
        self, activation_service: ActivationFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A well-formed KSL1 key, genuinely signed - but not by the key
        this app actually trusts (LICENSE_SIGNING_PUBLIC_KEY is left as the
        real embedded constant, not monkeypatched, so an unrelated keypair's
        signature must fail)."""
        service, _, _ = activation_service
        unrelated_private_key = Ed25519PrivateKey.generate()
        key = encode_license_key(
            {
                "license_id": "lic-x",
                "edition": "professional",
                "issued_to": "Someone",
                "email": "",
                "issued_at": "",
                "expires_at": "",
                "max_users": None,
                "max_organizations": None,
                "features": [],
            },
            unrelated_private_key,
        )
        with pytest.raises(InvalidLicenseKeyError):
            service.activate(key)

    def test_duplicate_key_is_rejected(
        self, activation_service: ActivationFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _, _ = activation_service
        key = _signed_key(monkeypatch)
        service.activate(key)

        with pytest.raises(ValueError, match="already activated"):
            service.activate(key)


class TestActivateBuildsLicenseFromVerifiedPayload:
    def test_edition_and_fields_come_from_payload_not_a_hardcoded_default(
        self, activation_service: ActivationFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _, _ = activation_service
        key = _signed_key(
            monkeypatch,
            edition="enterprise",
            issued_to="Widgets Inc",
            email="ops@widgets.example",
            max_users=250,
        )

        lic = service.activate(key)

        assert lic.edition == LicenseEdition.ENTERPRISE
        assert lic.issued_to == "Widgets Inc"
        assert lic.email == "ops@widgets.example"
        assert lic.max_users == 250
        assert lic.status == LicenseStatus.ACTIVE
        assert lic.is_legacy_activation is False
        assert lic.signature  # a real signature was stored, not blank

    def test_audit_entry_records_verified_edition(
        self, activation_service: ActivationFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, _, audit = activation_service
        key = _signed_key(monkeypatch, edition="community")

        service.activate(key)

        assert len(audit.entries) == 1


class TestRenewIsRetired:
    def test_renew_always_raises(self, activation_service: ActivationFixture) -> None:
        service, _, _ = activation_service
        with pytest.raises(ValueError, match="not supported"):
            service.renew("any-key", "professional", "")


class TestLegacyTimeBoxing:
    """Legacy licenses (activated before signing existed) have no
    cryptographic signature - the validator's time-boxing policy is the
    only thing that governs their status."""

    def _legacy_license(self, edition: LicenseEdition, *, expires_at: str = "", created_at: str) -> License:
        return License(
            id=LicenseId.generate(),
            edition=edition,
            status=LicenseStatus.ACTIVE,
            license_key="OLD-PLAIN-STRING-KEY",  # no KSL1. prefix -> legacy
            issued_to="Legacy Customer",
            expires_at=expires_at,
            created_at=created_at,
            updated_at=created_at,
        )

    def test_legacy_community_is_active_indefinitely(self) -> None:
        repo = _InMemoryLicenseRepository()
        validator = LicenseValidatorImpl(repo)
        very_old = (datetime.now(UTC) - timedelta(days=3650)).isoformat()
        lic = self._legacy_license(LicenseEdition.COMMUNITY, created_at=very_old)

        assert validator.validate(lic) == LicenseStatus.ACTIVE

    def test_legacy_professional_with_past_expiry_is_expired(self) -> None:
        repo = _InMemoryLicenseRepository()
        validator = LicenseValidatorImpl(repo)
        long_ago = (datetime.now(UTC) - timedelta(days=400)).isoformat()
        lic = self._legacy_license(LicenseEdition.PROFESSIONAL, expires_at=long_ago, created_at=long_ago)

        assert validator.validate(lic) == LicenseStatus.EXPIRED

    def test_legacy_professional_perpetual_recent_activation_is_active(self) -> None:
        repo = _InMemoryLicenseRepository()
        validator = LicenseValidatorImpl(repo)
        recent = (datetime.now(UTC) - timedelta(days=5)).isoformat()
        lic = self._legacy_license(LicenseEdition.PROFESSIONAL, created_at=recent)

        assert validator.validate(lic) == LicenseStatus.ACTIVE

    def test_legacy_professional_perpetual_beyond_grace_window_is_expired(self) -> None:
        repo = _InMemoryLicenseRepository()
        validator = LicenseValidatorImpl(repo)
        beyond_grace = (
            datetime.now(UTC)
            - timedelta(days=LicenseValidatorImpl.LEGACY_PERPETUAL_GRACE_DAYS + LicenseValidatorImpl.GRACE_DAYS + 1)
        ).isoformat()
        lic = self._legacy_license(LicenseEdition.PROFESSIONAL, created_at=beyond_grace)

        assert validator.validate(lic) == LicenseStatus.EXPIRED

    def test_legacy_signature_never_verifies(self) -> None:
        repo = _InMemoryLicenseRepository()
        validator = LicenseValidatorImpl(repo)
        lic = self._legacy_license(LicenseEdition.PROFESSIONAL, created_at=datetime.now(UTC).isoformat())

        assert validator.verify_signature(lic) is False


class TestSignedLicenseAtRestTampering:
    def test_validate_revokes_a_hand_edited_signed_license(
        self, activation_service: ActivationFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The concrete scenario from the build task: flip `edition`
        directly (simulating a raw SQL edit) on an already-activated,
        signed license, then confirm the next status check catches it."""
        service, repo, _ = activation_service
        key = _signed_key(monkeypatch, edition="professional")
        lic = service.activate(key)

        lic.edition = LicenseEdition.ENTERPRISE  # simulated tampering
        repo.save(lic)

        validator = LicenseValidatorImpl(repo)
        assert validator.validate(lic) == LicenseStatus.REVOKED

    def test_validate_accepts_an_untouched_signed_license(
        self, activation_service: ActivationFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        service, repo, _ = activation_service
        key = _signed_key(monkeypatch, edition="professional")
        lic = service.activate(key)

        validator = LicenseValidatorImpl(repo)
        assert validator.validate(lic) == LicenseStatus.ACTIVE
