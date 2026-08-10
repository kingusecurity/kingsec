"""Unit tests for the KSL1 signed-license-key codec.

Covers the two properties the whole license-validation redesign exists for:
a garbage/typed-in string is rejected outright, and a payload tampered with
after signing is detected - neither was true of the old self-signed hash().
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kingsec.application.services.license_key_codec import (
    InvalidLicenseKeyError,
    encode_license_key,
    license_to_signed_payload,
    parse_and_verify_license_key,
    verify_stored_signature,
)
from kingsec.domain.license import License, LicenseEdition, LicenseId, LicenseStatus


def _keypair() -> tuple[Ed25519PrivateKey, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes_raw()
    return private_key, public_key_bytes


def _payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "license_id": "lic-test0001",
        "edition": "professional",
        "issued_to": "Acme Corp",
        "email": "admin@acme.com",
        "issued_at": "2026-08-10T00:00:00+00:00",
        "expires_at": "",
        "max_users": None,
        "max_organizations": None,
        "features": [],
    }
    base.update(overrides)
    return base


class TestEncodeAndVerify:
    def test_round_trip_succeeds(self) -> None:
        private_key, public_key_bytes = _keypair()
        key = encode_license_key(_payload(), private_key)

        verified = parse_and_verify_license_key(key, public_key_bytes)

        assert verified.payload["edition"] == "professional"
        assert verified.payload["issued_to"] == "Acme Corp"
        assert verified.signature_b64

    def test_key_has_expected_prefix_and_shape(self) -> None:
        private_key, _ = _keypair()
        key = encode_license_key(_payload(), private_key)

        assert key.startswith("KSL1.")
        assert key.count(".") == 2  # KSL1 . payload . signature


class TestRejectsGarbageAndTampering:
    def test_arbitrary_string_is_rejected(self) -> None:
        _, public_key_bytes = _keypair()
        with pytest.raises(InvalidLicenseKeyError, match="Not a signed license key"):
            parse_and_verify_license_key("KS-BOGUS-KEY-0000", public_key_bytes)

    def test_empty_string_is_rejected(self) -> None:
        _, public_key_bytes = _keypair()
        with pytest.raises(InvalidLicenseKeyError):
            parse_and_verify_license_key("", public_key_bytes)

    def test_wrong_public_key_is_rejected(self) -> None:
        """The exact case that matters: a real, well-formed, genuinely
        signed key - but verified against a *different* keypair's public
        key. This is what "not issued by the real signer" looks like."""
        private_key, _ = _keypair()
        _, someone_elses_public_key = _keypair()
        key = encode_license_key(_payload(), private_key)

        with pytest.raises(InvalidLicenseKeyError, match="does not verify"):
            parse_and_verify_license_key(key, someone_elses_public_key)

    def test_tampered_payload_is_rejected(self) -> None:
        """Flip one character in the payload segment after signing -
        the exact scenario the build task asks to verify."""
        private_key, public_key_bytes = _keypair()
        key = encode_license_key(_payload(edition="community"), private_key)
        prefix, payload_b64, signature_b64 = key.split(".")

        # Flip the last character of the payload segment - guaranteed to
        # change the decoded bytes (base64url alphabet has no aliasing here).
        last_char = payload_b64[-1]
        replacement = "A" if last_char != "A" else "B"
        tampered_payload_b64 = payload_b64[:-1] + replacement
        tampered_key = f"{prefix}.{tampered_payload_b64}.{signature_b64}"

        with pytest.raises(InvalidLicenseKeyError):
            parse_and_verify_license_key(tampered_key, public_key_bytes)

    def test_malformed_structure_is_rejected(self) -> None:
        _, public_key_bytes = _keypair()
        with pytest.raises(InvalidLicenseKeyError, match="Malformed"):
            parse_and_verify_license_key("KSL1.only-one-part", public_key_bytes)

    def test_unknown_edition_is_rejected(self) -> None:
        private_key, public_key_bytes = _keypair()
        key = encode_license_key(_payload(edition="ultra-mega-tier"), private_key)

        with pytest.raises(InvalidLicenseKeyError, match="Unknown license edition"):
            parse_and_verify_license_key(key, public_key_bytes)

    def test_missing_required_field_is_rejected(self) -> None:
        private_key, public_key_bytes = _keypair()
        payload = _payload()
        del payload["issued_to"]
        key = encode_license_key(payload, private_key)

        with pytest.raises(InvalidLicenseKeyError, match="missing required fields"):
            parse_and_verify_license_key(key, public_key_bytes)


class TestAtRestVerification:
    """verify_stored_signature reconstructs the payload from *current*
    License fields and checks it against the *stored* signature - this is
    what catches a hand-edited DB row after activation."""

    def _activated_license(self, private_key: Ed25519PrivateKey) -> License:
        payload = _payload(edition="professional", max_users=10)
        key = encode_license_key(payload, private_key)
        # Simulate what LicenseActivationService.activate() does: build the
        # License from the verified payload's own fields.
        max_users = payload["max_users"]
        max_organizations = payload["max_organizations"]
        features = payload["features"]
        assert max_users is None or isinstance(max_users, int)
        assert max_organizations is None or isinstance(max_organizations, int)
        assert isinstance(features, list)
        return License(
            id=LicenseId(value=str(payload["license_id"])),
            edition=LicenseEdition(str(payload["edition"])),
            status=LicenseStatus.ACTIVE,
            license_key=key,
            issued_to=str(payload["issued_to"]),
            email=str(payload["email"]),
            max_users=max_users,
            max_organizations=max_organizations,
            issued_at=str(payload["issued_at"]),
            expires_at=str(payload["expires_at"]),
            features=set(features),
            signature=key.split(".")[2],
        )

    def test_untouched_license_verifies(self) -> None:
        private_key, public_key_bytes = _keypair()
        lic = self._activated_license(private_key)

        payload = license_to_signed_payload(lic)
        assert verify_stored_signature(payload, lic.signature, public_key_bytes) is True

    def test_hand_edited_edition_fails_verification(self) -> None:
        """The concrete scenario: someone flips `edition` directly via SQL
        on an already-activated, signed license."""
        private_key, public_key_bytes = _keypair()
        lic = self._activated_license(private_key)

        lic.edition = LicenseEdition.ENTERPRISE  # simulated SQL tampering

        payload = license_to_signed_payload(lic)
        assert verify_stored_signature(payload, lic.signature, public_key_bytes) is False

    def test_hand_edited_max_users_fails_verification(self) -> None:
        private_key, public_key_bytes = _keypair()
        lic = self._activated_license(private_key)

        lic.max_users = 999999  # simulated SQL tampering

        payload = license_to_signed_payload(lic)
        assert verify_stored_signature(payload, lic.signature, public_key_bytes) is False

    def test_missing_signature_fails_verification(self) -> None:
        private_key, public_key_bytes = _keypair()
        lic = self._activated_license(private_key)
        payload = license_to_signed_payload(lic)

        assert verify_stored_signature(payload, "", public_key_bytes) is False
