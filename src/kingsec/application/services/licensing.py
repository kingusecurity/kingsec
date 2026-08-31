from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from kingsec.application.ports.outbound.license_repository import LicenseRepository
from kingsec.application.ports.outbound.license_validator import LicenseValidator
from kingsec.application.services.license_key_codec import (
    InvalidLicenseKeyError,
    license_to_signed_payload,
    parse_and_verify_license_key,
    verify_stored_signature,
)
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.license import (
    EDITION_FEATURES,
    EDITION_LIMITS,
    LICENSE_SIGNING_PUBLIC_KEY,
    License,
    LicenseEdition,
    LicenseId,
    LicenseStatus,
)
from kingsec.shared.errors import PersistenceError

_logger = logging.getLogger("kingsec.application.services.licensing")

__all__ = [
    "InvalidLicenseKeyError",
    "LicenseActivationService",
    "LicenseGate",
    "LicenseValidatorImpl",
]


class LicenseGate:
    """Centralized feature gate — the ONLY place edition checks are scattered.

    If no license is configured, features default to Community Edition.
    """

    def __init__(self, repo: LicenseRepository, validator: LicenseValidator) -> None:
        self._repo = repo
        self._validator = validator

    def _get_license(self) -> License | None:
        """Look up the active license, failing CLOSED to "no license" (i.e.
        Community edition, via the existing ``lic is None`` branches in
        ``_check``/``_limit``/etc.) if the repository itself is unavailable.

        A database outage must never be interpreted as "license checks pass" -
        that would silently grant paid features during an incident. Only the
        repository's own translated ``PersistenceError`` is caught here (never
        a blanket ``Exception``), so a real bug elsewhere in this class still
        propagates normally.
        """
        try:
            return self._repo.find_active()
        except PersistenceError:
            _logger.error("license repository unavailable; failing closed to Community edition", exc_info=True)
            return None

    def _check(self, feature: str) -> bool:
        lic = self._get_license()
        if lic is None:
            return feature in EDITION_FEATURES[LicenseEdition.COMMUNITY]
        if not lic.is_active:
            return feature in EDITION_FEATURES[LicenseEdition.COMMUNITY]
        return self._validator.has_feature(lic, feature)

    def _limit(self, name: str) -> int | None:
        lic = self._get_license()
        if lic is None:
            return EDITION_LIMITS[LicenseEdition.COMMUNITY].get(name)
        if not lic.is_active:
            return EDITION_LIMITS[LicenseEdition.COMMUNITY].get(name)
        return lic.effective_limits().get(name)

    # ── Feature gates ──────────────────────────────────────────────────────

    def can_use_integrations(self) -> bool:
        return self._check("integrations")

    def can_use_scheduling(self) -> bool:
        return self._check("scheduling")

    def can_use_api_keys(self) -> bool:
        return self._check("api_keys")

    def can_use_advanced_reports(self) -> bool:
        return self._check("advanced_reports")

    def can_use_sso(self) -> bool:
        return self._check("sso")

    def can_use_priority_support(self) -> bool:
        return self._check("priority_support")

    def can_use_enterprise_audit(self) -> bool:
        return self._check("enterprise_audit")

    def can_use_custom_roles(self) -> bool:
        return self._check("custom_roles")

    def can_use_custom_branding(self) -> bool:
        return self._check("custom_branding")

    def can_create_multiple_orgs(self) -> bool:
        return self._check("unlimited_orgs")

    def can_use_team_collaboration(self) -> bool:
        return self._check("team_collaboration")

    # ── Limit checks ───────────────────────────────────────────────────────

    def max_users(self) -> int | None:
        return self._limit("max_users")

    def max_organizations(self) -> int | None:
        return self._limit("max_organizations")

    def max_api_keys(self) -> int | None:
        return self._limit("max_api_keys")

    # ── Edition info ───────────────────────────────────────────────────────

    def current_edition(self) -> LicenseEdition:
        lic = self._get_license()
        return lic.edition if lic else LicenseEdition.COMMUNITY

    def current_status(self) -> LicenseStatus:
        lic = self._get_license()
        return lic.status if lic else LicenseStatus.INACTIVE

    def current_license(self) -> License | None:
        return self._get_license()

    def enabled_features(self) -> set[str]:
        lic = self._get_license()
        if lic is None:
            return EDITION_FEATURES[LicenseEdition.COMMUNITY]
        if not lic.is_active:
            return EDITION_FEATURES[LicenseEdition.COMMUNITY]
        return lic.effective_features()


class LicenseValidatorImpl(LicenseValidator):
    """Validates licenses with offline signed-key verification, expiration,
    feature flags, tamper detection, and clock rollback protection.

    Signed (``KSL1.``) licenses get the real thing: ``verify_signature``
    checks the stored signature against the license's *current* stored
    fields using the embedded Ed25519 public key, so hand-editing any signed
    column (e.g. flipping ``edition`` directly via SQL) is detected on the
    next status check.

    Legacy licenses (activated before real signing existed) carry no
    cryptographic signature at all - there is nothing to verify - so they
    get a time-boxing policy instead: Community is tolerated indefinitely
    (there's nothing to protect there), Professional/Enterprise are honored
    until their existing ``expires_at``, or a fixed grace window from
    original activation if perpetual. This is deliberately more forgiving
    than "reject immediately" - the point is not to silently break every
    already-installed license the moment this ships.
    """

    GRACE_DAYS = 30
    LEGACY_PERPETUAL_GRACE_DAYS = 180

    def __init__(self, repo: LicenseRepository) -> None:
        self._repo = repo

    def validate(self, license: License) -> LicenseStatus:
        if license.status == LicenseStatus.REVOKED:
            return LicenseStatus.REVOKED
        if license.is_legacy_activation:
            return self._legacy_status(license)
        status = self.check_expiration(license)
        if status in (LicenseStatus.EXPIRED, LicenseStatus.GRACE_PERIOD):
            return status
        if not self.verify_signature(license):
            return LicenseStatus.REVOKED
        if self.detect_clock_rollback(license):
            return LicenseStatus.REVOKED
        return LicenseStatus.ACTIVE

    def verify_signature(self, license: License) -> bool:
        """Verify the stored signature against the license's current stored
        fields - not a recompute-and-compare, a real cryptographic check.

        Always False for a legacy license (there is no signature to
        verify); ``validate()`` never reaches this for one, but a direct
        caller gets an honest answer rather than a misleading pass.
        """
        if license.is_legacy_activation:
            return False
        payload = license_to_signed_payload(license)
        return verify_stored_signature(payload, license.signature, LICENSE_SIGNING_PUBLIC_KEY)

    def check_expiration(self, license: License) -> LicenseStatus:
        if not license.expires_at:
            return LicenseStatus.ACTIVE
        try:
            expiry = datetime.fromisoformat(license.expires_at)
        except (ValueError, TypeError):
            return LicenseStatus.ACTIVE
        now = datetime.now(UTC)
        if now < expiry:
            return LicenseStatus.ACTIVE
        if now < expiry + timedelta(days=self.GRACE_DAYS):
            return LicenseStatus.GRACE_PERIOD
        return LicenseStatus.EXPIRED

    def _legacy_status(self, license: License) -> LicenseStatus:
        if license.edition == LicenseEdition.COMMUNITY:
            return LicenseStatus.ACTIVE
        if license.expires_at:
            return self.check_expiration(license)
        # Perpetual legacy Professional/Enterprise: a fixed grace window
        # counted from original activation (created_at), not from "now" -
        # a stable cutoff per license rather than one that keeps moving.
        try:
            activated = datetime.fromisoformat(license.created_at)
        except (ValueError, TypeError):
            return LicenseStatus.ACTIVE
        now = datetime.now(UTC)
        cutoff = activated + timedelta(days=self.LEGACY_PERPETUAL_GRACE_DAYS)
        if now < cutoff:
            return LicenseStatus.ACTIVE
        if now < cutoff + timedelta(days=self.GRACE_DAYS):
            return LicenseStatus.GRACE_PERIOD
        return LicenseStatus.EXPIRED

    def has_feature(self, license: License, feature: str) -> bool:
        return feature in license.effective_features()

    def detect_clock_rollback(self, license: License) -> bool:
        if not license.updated_at:
            return False
        try:
            last_updated = datetime.fromisoformat(license.updated_at)
        except (ValueError, TypeError):
            return False
        now = datetime.now(UTC)
        return now < last_updated - timedelta(hours=1)


class LicenseActivationService:
    """Manages license activation, deactivation, and renewal."""

    def __init__(
        self,
        repo: LicenseRepository,
        validator: LicenseValidator,
        gate: LicenseGate,
        audit: Any,
    ) -> None:
        self._repo = repo
        self._validator = validator
        self._gate = gate
        self._audit = audit

    def activate(self, license_key: str, user_id: str = "") -> License:
        """Activate a real, signed license key.

        Only ``KSL1.`` keys are accepted here - the parse step verifies the
        Ed25519 signature against the embedded public key, so a garbage
        string or a tampered payload is rejected outright, and the
        edition/limits/features come from the *verified* payload, never
        from a hardcoded default. Raises ``InvalidLicenseKeyError`` (a
        ``ValueError`` subclass) for anything that fails to parse or verify.
        """
        existing = self._repo.find_by_key(license_key)
        if existing:
            raise ValueError("License key already activated")

        verified = parse_and_verify_license_key(license_key, LICENSE_SIGNING_PUBLIC_KEY)
        payload = verified.payload

        lic = License(
            id=LicenseId(value=payload["license_id"]),
            edition=LicenseEdition(payload["edition"]),
            status=LicenseStatus.ACTIVE,
            license_key=license_key,
            issued_to=payload["issued_to"],
            email=payload.get("email", ""),
            max_users=payload.get("max_users"),
            max_organizations=payload.get("max_organizations"),
            issued_at=payload.get("issued_at", ""),
            expires_at=payload.get("expires_at", ""),
            features=set(payload.get("features", [])),
            signature=verified.signature_b64,
        )
        self._repo.save(lic)
        self._audit.record(AuditEntry(
            action=AuditAction.LICENSE_ACTIVATED,
            resource_type="license",
            resource_id=str(lic.id),
            user_id=user_id,
            metadata={"edition": lic.edition.value, "license_key_suffix": license_key[-8:]},
        ))
        return lic

    def deactivate(self, license_id: str, user_id: str = "") -> None:
        lic = self._repo.find_active()
        if lic is None or str(lic.id) != license_id:
            raise ValueError("License not found")
        lic.status = LicenseStatus.INACTIVE
        self._repo.save(lic)
        self._audit.record(AuditEntry(
            action=AuditAction.LICENSE_DEACTIVATED,
            resource_type="license",
            resource_id=license_id,
            user_id=user_id,
        ))

    def renew(self, license_key: str, edition: str, expires_at: str, features: list[str] | None = None,
              user_id: str = "") -> License:
        """Not supported for either license format - kept only so a caller
        gets a clear, actionable error instead of the method vanishing.

        A signed license's fields are cryptographically fixed by the
        issuer; mutating them locally and re-signing with a self-computed
        value is exactly the vulnerability this whole scheme replaces, so
        there is no "renew in place" for a KSL1 license. A legacy license
        is explicitly excluded from any renewal path by policy (see
        LicenseValidatorImpl's time-boxing). Either way, the real fix is
        the same: issue a new signed key (tools/issue_license.py) and
        activate it - see LicenseActivationService.activate().
        """
        raise ValueError(
            "License renewal by field mutation is not supported. "
            "Issue a new signed license key and activate it instead."
        )

    def get_status(self) -> dict[str, Any]:
        lic = self._gate.current_license()
        if lic is None:
            return {
                "edition": LicenseEdition.COMMUNITY.value,
                "status": LicenseStatus.INACTIVE.value,
                "features": sorted(EDITION_FEATURES[LicenseEdition.COMMUNITY]),
                "limits": dict(EDITION_LIMITS[LicenseEdition.COMMUNITY]),
                "has_license": False,
            }
        status = self._validator.validate(lic)
        if status != lic.status and lic.status != LicenseStatus.INACTIVE:
            lic.status = status
            self._repo.save(lic)
            if status in (LicenseStatus.EXPIRED, LicenseStatus.GRACE_PERIOD):
                self._audit.record(AuditEntry(
                    action=AuditAction.LICENSE_EXPIRED,
                    resource_type="license",
                    resource_id=str(lic.id),
                    metadata={"status": status.value},
                ))
        return {
            "id": str(lic.id),
            "edition": lic.edition.value,
            "status": lic.status.value,
            "license_key": lic.license_key[-8:],
            "issued_to": lic.issued_to,
            "company": lic.company,
            "email": lic.email,
            "issued_at": lic.issued_at,
            "expires_at": lic.expires_at,
            "features": sorted(lic.effective_features()),
            "limits": lic.effective_limits(),
            "has_license": True,
            "grace_days": LicenseValidatorImpl.GRACE_DAYS,
            "is_legacy_activation": lic.is_legacy_activation,
        }
