"""License parser and machine binding for offline license validation.

Parses license keys in the format: KS-{edition}-{key}
Validates license structure, extracts components, and supports
optional machine binding via hardware fingerprint.
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from kingsec.domain.license import LicenseEdition


class LicenseParseError(ValueError):
    """Raised when a license key cannot be parsed."""


@dataclass(frozen=True)
class ParsedLicense:
    """Components extracted from a parsed license key."""

    edition: LicenseEdition
    customer_name: str
    company: str
    email: str
    issued_at: datetime
    expires_at: datetime | None
    max_users: int | None
    max_assets: int | None
    max_workers: int | None
    enabled_features: tuple[str, ...]
    signature: str
    machine_id: str | None
    raw_key: str


_LICENSE_PREFIX = "KS"


def parse_license_key(license_key: str) -> ParsedLicense:
    """Parse a license key string into its components.

    Expected format (base64-encoded JSON after prefix):
        KS-{base64_encoded_json}

    The JSON payload contains:
        - edition: str
        - customer_name: str
        - company: str
        - email: str
        - issued_at: ISO format
        - expires_at: ISO format or null
        - max_users: int or null
        - max_assets: int or null
        - max_workers: int or null
        - enabled_features: list[str]
        - signature: str
        - machine_id: str or null
    """
    import base64

    if not license_key:
        raise LicenseParseError("License key is empty")

    parts = license_key.split("-", 1)
    if len(parts) != 2 or parts[0] != _LICENSE_PREFIX:
        raise LicenseParseError(
            f"Invalid license key format. Expected '{_LICENSE_PREFIX}-{{payload}}', got {license_key[:20]}..."
        )

    try:
        payload_b64 = parts[1]
        # Add padding if needed
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += "=" * padding
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise LicenseParseError(f"Failed to decode license payload: {exc}") from exc

    return _payload_to_license(payload, license_key)


def _payload_to_license(payload: dict[str, Any], raw_key: str) -> ParsedLicense:
    """Convert a decoded JSON payload to a ParsedLicense."""
    required = {"edition", "customer_name", "company", "email", "issued_at", "signature"}
    missing = required - set(payload.keys())
    if missing:
        raise LicenseParseError(f"Missing required license fields: {missing}")

    try:
        edition = LicenseEdition(payload["edition"])
    except ValueError:
        raise LicenseParseError(f"Unknown edition: {payload['edition']}") from None

    try:
        issued_at = datetime.fromisoformat(payload["issued_at"])
    except (ValueError, TypeError) as exc:
        raise LicenseParseError(f"Invalid issued_at: {exc}") from exc

    expires_at = None
    if payload.get("expires_at"):
        try:
            expires_at = datetime.fromisoformat(payload["expires_at"])
        except (ValueError, TypeError) as exc:
            raise LicenseParseError(f"Invalid expires_at: {exc}") from exc

    features = tuple(payload.get("enabled_features", []))

    return ParsedLicense(
        edition=edition,
        customer_name=payload["customer_name"],
        company=payload["company"],
        email=payload["email"],
        issued_at=issued_at,
        expires_at=expires_at,
        max_users=payload.get("max_users"),
        max_assets=payload.get("max_assets"),
        max_workers=payload.get("max_workers"),
        enabled_features=features,
        signature=payload["signature"],
        machine_id=payload.get("machine_id"),
        raw_key=raw_key,
    )


def compute_machine_id() -> str:
    """Compute a stable machine fingerprint.

    Uses a combination of hostname, MAC address, and machine ID
    to generate a deterministic machine fingerprint. Returns a
    SHA-256 hex digest.
    """
    components: list[str] = []
    components.append(platform.node())
    components.append(str(uuid.getnode()))
    # Linux machine-id
    try:
        with open("/etc/machine-id") as f:
            components.append(f.read().strip())
    except (FileNotFoundError, PermissionError):
        pass
    # Windows machine GUID. Gated on sys.platform (not a bare try/import) so
    # mypy's platform-aware narrowing - pinned to "linux" in pyproject.toml,
    # matching the container this project ships in - can prove this branch
    # unreachable there instead of resolving winreg's members against
    # whatever OS happens to be running the type checker. That also means
    # this branch is unchecked by mypy on every platform; see Phase 20's
    # report for the tradeoff.
    if sys.platform == "win32":
        import winreg

        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            components.append(str(guid))
            winreg.CloseKey(key)
        except OSError:
            pass

    combined = "|".join(components)
    return hashlib.sha256(combined.encode()).hexdigest()


def validate_machine_binding(parsed: ParsedLicense) -> bool:
    """Check if the license is bound to this machine.

    Returns True if:
    - No machine_id is set (not bound), or
    - The machine_id matches the current machine fingerprint
    """
    if not parsed.machine_id:
        return True
    return parsed.machine_id == compute_machine_id()


def create_license_payload(
    *,
    edition: LicenseEdition,
    customer_name: str,
    company: str,
    email: str,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    max_users: int | None = None,
    max_assets: int | None = None,
    max_workers: int | None = None,
    enabled_features: tuple[str, ...] = (),
    secret_key: str,
    machine_id: str | None = None,
) -> str:
    """Create a signed license key (for internal/licensor use)."""
    import base64
    import hmac

    now = issued_at or datetime.now(UTC)
    payload = {
        "edition": edition.value,
        "customer_name": customer_name,
        "company": company,
        "email": email,
        "issued_at": now.isoformat(),
        "expires_at": expires_at.isoformat() if expires_at else None,
        "max_users": max_users,
        "max_assets": max_assets,
        "max_workers": max_workers,
        "enabled_features": list(enabled_features),
        "machine_id": machine_id,
    }

    # Compute signature over the payload (without signature field)
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signature = hmac.new(
        secret_key.encode(), payload_json.encode(), hashlib.sha256
    ).hexdigest()
    payload["signature"] = signature

    # Encode as base64
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    # Remove padding for cleaner key
    encoded = encoded.rstrip("=")
    return f"{_LICENSE_PREFIX}-{encoded}"
