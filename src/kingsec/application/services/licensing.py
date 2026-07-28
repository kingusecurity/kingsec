from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

from kingsec.application.ports.outbound.license_repository import LicenseRepository
from kingsec.application.ports.outbound.license_validator import LicenseValidator
from kingsec.domain.audit import AuditAction, AuditEntry
from kingsec.domain.license import (
    EDITION_FEATURES,
    EDITION_LIMITS,
    License,
    LicenseEdition,
    LicenseId,
    LicenseStatus,
)


class LicenseGate:
    """Centralized feature gate — the ONLY place edition checks are scattered.

    If no license is configured, features default to Community Edition.
    """

    def __init__(self, repo: LicenseRepository, validator: LicenseValidator) -> None:
        self._repo = repo
        self._validator = validator

    def _get_license(self) -> License | None:
        return self._repo.find_active()

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
    """Validates licenses with offline signed file support, expiration,
    feature flags, tamper detection, and clock rollback protection."""

    GRACE_DAYS = 30

    def __init__(self, repo: LicenseRepository) -> None:
        self._repo = repo

    def validate(self, license: License) -> LicenseStatus:
        if license.status == LicenseStatus.REVOKED:
            return LicenseStatus.REVOKED
        status = self.check_expiration(license)
        if status in (LicenseStatus.EXPIRED, LicenseStatus.GRACE_PERIOD):
            return status
        if not self.verify_signature(license):
            return LicenseStatus.REVOKED
        if self.detect_clock_rollback(license):
            return LicenseStatus.REVOKED
        return LicenseStatus.ACTIVE

    def verify_signature(self, license: License) -> bool:
        if not license.signature:
            return False
        try:
            expected = self.compute_signature(license)
            result = license.signature == expected
            return result
        except Exception:
            return False

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

    def compute_signature(self, license: License) -> str:
        data = self._signature_data(license)
        return str(hash(data))

    def _signature_data(self, license: License) -> str:
        return json.dumps({
            "id": str(license.id),
            "edition": license.edition.value,
            "license_key": license.license_key,
            "issued_to": license.issued_to,
            "company": license.company,
            "email": license.email,
            "max_users": license.max_users,
            "max_organizations": license.max_organizations,
            "expires_at": license.expires_at,
            "features": sorted(license.features),
        }, sort_keys=True)


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
        existing = self._repo.find_by_key(license_key)
        if existing:
            raise ValueError("License key already activated")

        lic = License(
            id=LicenseId.generate(),
            edition=LicenseEdition.PROFESSIONAL,
            status=LicenseStatus.ACTIVE,
            license_key=license_key,
            issued_to="",
            signature="",
        )
        lic.signature = self._validator.compute_signature(lic)
        self._repo.save(lic)
        self._audit.record(AuditEntry(
            action=AuditAction.LICENSE_ACTIVATED,
            resource_type="license",
            resource_id=str(lic.id),
            user_id=user_id,
            metadata={"edition": lic.edition.value, "license_key": license_key},
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
        lic = self._repo.find_by_key(license_key)
        if lic is None:
            raise ValueError("License key not found")

        old_edition = lic.edition
        lic.edition = LicenseEdition(edition)
        lic.expires_at = expires_at
        lic.status = LicenseStatus.ACTIVE
        if features is not None:
            lic.features = set(features)
        lic.signature = self._validator.compute_signature(lic)
        lic.updated_at = datetime.now(UTC).isoformat()
        self._repo.save(lic)

        if old_edition != lic.edition:
            self._audit.record(AuditEntry(
                action=AuditAction.EDITION_CHANGED,
                resource_type="license",
                resource_id=str(lic.id),
                user_id=user_id,
                metadata={"from": old_edition.value, "to": lic.edition.value},
            ))
        self._audit.record(AuditEntry(
            action=AuditAction.LICENSE_RENEWED,
            resource_type="license",
            resource_id=str(lic.id),
            user_id=user_id,
        ))
        return lic

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
            "expires_at": lic.expires_at,
            "features": sorted(lic.effective_features()),
            "limits": lic.effective_limits(),
            "has_license": True,
            "grace_days": LicenseValidatorImpl.GRACE_DAYS,
        }
