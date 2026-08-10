from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

# Format tag for a real, cryptographically signed license key
# ("KSL1.<base64url payload>.<base64url Ed25519 signature>"). Any license_key
# that doesn't start with this prefix is a legacy, unvalidated activation —
# see LicenseValidatorImpl in application/services/licensing.py for how the
# two are treated differently.
SIGNED_KEY_PREFIX = "KSL1."

# The Ed25519 public key used to verify every signed license key, as raw
# 32-byte key material. Public keys are not secret - embedding this constant
# in source and shipping it with the app is the correct, expected mechanism
# for fully offline signature verification (KingSec does not phone home).
# The matching private key is held only by whoever issues licenses; it is
# never committed and never shipped - see keys/README.md and
# tools/issue_license.py. Rotating this key invalidates every license signed
# under the old one; that is an intentional consequence of rotation.
LICENSE_SIGNING_PUBLIC_KEY: bytes = bytes.fromhex(
    "f22b7bbb7cd235e97595ebf294ae4a8fcf89f4aa1e32288a008ce7f664b8eb55"
)


def is_signed_license_key(license_key: str) -> bool:
    """True for a real, cryptographically signed key; False for a legacy one.

    A pure format check (does it carry the KSL1 tag) - actual signature
    verification happens separately in LicenseValidatorImpl, which needs the
    cryptography library and therefore lives outside this dependency-free
    domain module.
    """
    return license_key.startswith(SIGNED_KEY_PREFIX)


class LicenseEdition(StrEnum):
    COMMUNITY = "community"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class LicenseStatus(StrEnum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    GRACE_PERIOD = "grace_period"
    INACTIVE = "inactive"


@dataclass(frozen=True)
class LicenseId:
    value: str

    def __str__(self) -> str:
        return self.value

    @classmethod
    def generate(cls) -> LicenseId:
        import uuid
        return cls(f"lic-{uuid.uuid4().hex}")


EDITION_FEATURES: dict[LicenseEdition, set[str]] = {
    LicenseEdition.COMMUNITY: {
        "core_scanners",
        "pdf_reports",
        "manual_assessments",
    },
    LicenseEdition.PROFESSIONAL: {
        "core_scanners",
        "pdf_reports",
        "manual_assessments",
        "scheduling",
        "integrations",
        "api_keys",
        "advanced_reports",
        "unlimited_users",
        "unlimited_orgs",
        "team_collaboration",
        "activity_feed",
    },
    LicenseEdition.ENTERPRISE: {
        "core_scanners",
        "pdf_reports",
        "manual_assessments",
        "scheduling",
        "integrations",
        "api_keys",
        "advanced_reports",
        "unlimited_users",
        "unlimited_orgs",
        "team_collaboration",
        "activity_feed",
        "sso",
        "priority_support",
        "enterprise_audit",
        "custom_roles",
        "audit_export",
        "data_retention",
        "custom_branding",
    },
}

EDITION_LIMITS: dict[LicenseEdition, dict[str, int | None]] = {
    LicenseEdition.COMMUNITY: {
        "max_users": 5,
        "max_organizations": 1,
        "max_api_keys": 3,
        "max_schedules": 0,
        "max_integrations": 0,
    },
    LicenseEdition.PROFESSIONAL: {
        "max_users": None,
        "max_organizations": None,
        "max_api_keys": None,
        "max_schedules": None,
        "max_integrations": None,
    },
    LicenseEdition.ENTERPRISE: {
        "max_users": None,
        "max_organizations": None,
        "max_api_keys": None,
        "max_schedules": None,
        "max_integrations": None,
    },
}


@dataclass
class License:
    id: LicenseId
    edition: LicenseEdition
    status: LicenseStatus
    license_key: str
    issued_to: str
    company: str = ""
    email: str = ""
    max_users: int | None = None
    max_organizations: int | None = None
    issued_at: str = ""
    expires_at: str = ""
    features: set[str] = field(default_factory=set)
    signature: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @property
    def is_active(self) -> bool:
        return self.status in (LicenseStatus.ACTIVE, LicenseStatus.GRACE_PERIOD)

    @property
    def is_expired(self) -> bool:
        return self.status == LicenseStatus.EXPIRED

    @property
    def is_legacy_activation(self) -> bool:
        """True for a license activated before real signature validation existed.

        These keep working (see LicenseValidatorImpl's time-boxing policy)
        but carry no cryptographic guarantee at all - the frontend surfaces
        this so nobody mistakes one for a validated license.
        """
        return not is_signed_license_key(self.license_key)

    def effective_features(self) -> set[str]:
        base = EDITION_FEATURES.get(self.edition, set())
        return base | self.features

    def effective_limits(self) -> dict[str, int | None]:
        defaults = dict(EDITION_LIMITS.get(self.edition, {}))
        if self.max_users is not None:
            defaults["max_users"] = self.max_users
        if self.max_organizations is not None:
            defaults["max_organizations"] = self.max_organizations
        return defaults
