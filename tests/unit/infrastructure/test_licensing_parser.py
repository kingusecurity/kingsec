"""Tests for licensing infrastructure (parser, machine binding, payload creation)."""

from datetime import UTC, datetime, timedelta

import pytest

from kingsec.domain.license import LicenseEdition
from kingsec.infrastructure.licensing.parser import (
    LicenseParseError,
    ParsedLicense,
    compute_machine_id,
    create_license_payload,
    parse_license_key,
    validate_machine_binding,
)


class TestLicenseParsing:
    """Tests for license key parsing."""

    def test_parse_valid_license_key(self):
        """Test parsing a valid license key."""
        key = create_license_payload(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test User",
            company="Test Corp",
            email="test@example.com",
            secret_key="test-secret-key-12345",
        )
        parsed = parse_license_key(key)
        assert parsed.edition == LicenseEdition.PROFESSIONAL
        assert parsed.customer_name == "Test User"
        assert parsed.company == "Test Corp"
        assert parsed.email == "test@example.com"

    def test_parse_empty_key_raises(self):
        """Test that empty key raises LicenseParseError."""
        with pytest.raises(LicenseParseError, match="empty"):
            parse_license_key("")

    def test_parse_invalid_prefix_raises(self):
        """Test that key without KS- prefix raises LicenseParseError."""
        with pytest.raises(LicenseParseError, match="Invalid license key format"):
            parse_license_key("INVALID-somepayload")

    def test_parse_corrupted_payload_raises(self):
        """Test that corrupted base64 payload raises LicenseParseError."""
        with pytest.raises(LicenseParseError, match="Failed to decode"):
            parse_license_key("KS-invalid-base64!!!")

    def test_parse_missing_required_fields_raises(self):
        """Test that payload missing required fields raises LicenseParseError."""
        import base64
        import json

        payload = {"edition": "professional"}  # Missing required fields
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        with pytest.raises(LicenseParseError, match="Missing required"):
            parse_license_key(f"KS-{encoded}")

    def test_parse_unknown_edition_raises(self):
        """Test that unknown edition raises LicenseParseError."""
        import base64
        import json

        payload = {
            "edition": "ultra",
            "customer_name": "Test",
            "company": "Test",
            "email": "test@test.com",
            "issued_at": datetime.now(UTC).isoformat(),
            "signature": "abc",
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        with pytest.raises(LicenseParseError, match="Unknown edition"):
            parse_license_key(f"KS-{encoded}")

    def test_parse_with_expiration(self):
        """Test parsing a license key with expiration date."""
        expires = datetime.now(UTC) + timedelta(days=365)
        key = create_license_payload(
            edition=LicenseEdition.ENTERPRISE,
            customer_name="Enterprise User",
            company="Big Corp",
            email="enterprise@bigcorp.com",
            expires_at=expires,
            secret_key="enterprise-secret-key",
        )
        parsed = parse_license_key(key)
        assert parsed.expires_at is not None
        assert parsed.edition == LicenseEdition.ENTERPRISE

    def test_parse_with_custom_features(self):
        """Test parsing a license key with custom features."""
        key = create_license_payload(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            enabled_features=("sso", "advanced_reporting", "custom_branding"),
            secret_key="feature-secret",
        )
        parsed = parse_license_key(key)
        assert "sso" in parsed.enabled_features
        assert "advanced_reporting" in parsed.enabled_features
        assert "custom_branding" in parsed.enabled_features

    def test_parse_roundtrip_preserves_fields(self):
        """Test that all fields survive a roundtrip through create/parse."""
        key = create_license_payload(
            edition=LicenseEdition.ENTERPRISE,
            customer_name="Roundtrip User",
            company="Round Corp",
            email="round@test.com",
            max_users=100,
            max_assets=500,
            max_workers=10,
            enabled_features=("sso", "audit_export"),
            secret_key="roundtrip-key",
        )
        parsed = parse_license_key(key)
        assert parsed.max_users == 100
        assert parsed.max_assets == 500
        assert parsed.max_workers == 10
        assert parsed.raw_key == key


class TestMachineBinding:
    """Tests for machine fingerprinting and binding."""

    def test_compute_machine_id_returns_string(self):
        """Test that compute_machine_id returns a non-empty string."""
        machine_id = compute_machine_id()
        assert isinstance(machine_id, str)
        assert len(machine_id) > 0

    def test_compute_machine_id_is_deterministic(self):
        """Test that machine ID is the same across calls."""
        id1 = compute_machine_id()
        id2 = compute_machine_id()
        assert id1 == id2

    def test_validate_machine_binding_no_machine_id(self):
        """Test that license without machine_id always passes."""
        parsed = ParsedLicense(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            issued_at=datetime.now(UTC),
            expires_at=None,
            max_users=None,
            max_assets=None,
            max_workers=None,
            enabled_features=(),
            signature="abc",
            machine_id=None,
            raw_key="KS-test",
        )
        assert validate_machine_binding(parsed) is True

    def test_validate_machine_binding_matching_id(self):
        """Test that matching machine_id passes."""
        machine_id = compute_machine_id()
        parsed = ParsedLicense(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            issued_at=datetime.now(UTC),
            expires_at=None,
            max_users=None,
            max_assets=None,
            max_workers=None,
            enabled_features=(),
            signature="abc",
            machine_id=machine_id,
            raw_key="KS-test",
        )
        assert validate_machine_binding(parsed) is True

    def test_validate_machine_binding_mismatched_id(self):
        """Test that mismatched machine_id fails."""
        parsed = ParsedLicense(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            issued_at=datetime.now(UTC),
            expires_at=None,
            max_users=None,
            max_assets=None,
            max_workers=None,
            enabled_features=(),
            signature="abc",
            machine_id="wrong-machine-id",
            raw_key="KS-test",
        )
        assert validate_machine_binding(parsed) is False


class TestLicensePayloadCreation:
    """Tests for license payload creation."""

    def test_create_payload_minimal(self):
        """Test creating a minimal license payload."""
        key = create_license_payload(
            edition=LicenseEdition.COMMUNITY,
            customer_name="Community User",
            company="Small Corp",
            email="community@small.com",
            secret_key="community-key",
        )
        assert key.startswith("KS-")
        parsed = parse_license_key(key)
        assert parsed.edition == LicenseEdition.COMMUNITY

    def test_create_payload_with_expiration(self):
        """Test creating a license with expiration."""
        expires = datetime(2027, 12, 31, tzinfo=UTC)
        key = create_license_payload(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Pro User",
            company="Pro Corp",
            email="pro@test.com",
            expires_at=expires,
            secret_key="pro-key",
        )
        parsed = parse_license_key(key)
        assert parsed.expires_at is not None
        assert parsed.expires_at.year == 2027

    def test_create_payload_with_limits(self):
        """Test creating a license with custom limits."""
        key = create_license_payload(
            edition=LicenseEdition.COMMUNITY,
            customer_name="Limited",
            company="Ltd",
            email="limited@test.com",
            max_users=5,
            max_assets=100,
            max_workers=2,
            secret_key="limited-key",
        )
        parsed = parse_license_key(key)
        assert parsed.max_users == 5
        assert parsed.max_assets == 100
        assert parsed.max_workers == 2

    def test_create_payload_signature_varies_by_key(self):
        """Test that different secret keys produce different signatures."""
        key1 = create_license_payload(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            secret_key="key-1",
        )
        key2 = create_license_payload(
            edition=LicenseEdition.PROFESSIONAL,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            secret_key="key-2",
        )
        parsed1 = parse_license_key(key1)
        parsed2 = parse_license_key(key2)
        assert parsed1.signature != parsed2.signature


class TestParsedLicenseDataclass:
    """Tests for ParsedLicense dataclass behavior."""

    def test_is_frozen(self):
        """Test that ParsedLicense is immutable."""
        parsed = ParsedLicense(
            edition=LicenseEdition.COMMUNITY,
            customer_name="Test",
            company="Test",
            email="test@test.com",
            issued_at=datetime.now(UTC),
            expires_at=None,
            max_users=None,
            max_assets=None,
            max_workers=None,
            enabled_features=(),
            signature="abc",
            machine_id=None,
            raw_key="KS-test",
        )
        with pytest.raises(AttributeError):
            parsed.customer_name = "Changed"  # type: ignore[misc]
