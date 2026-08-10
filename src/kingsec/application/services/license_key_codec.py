"""Encode, parse, and verify signed KingSec license keys.

Format: ``KSL1.<base64url payload>.<base64url Ed25519 signature>``

- ``payload``: canonical JSON (sorted keys, no whitespace) of the license's
  signed fields, base64url-encoded with no padding.
- ``signature``: the issuer's Ed25519 signature over the exact payload bytes
  (before base64 encoding), base64url-encoded with no padding.

Shared by ``tools/issue_license.py`` (signs - needs the private key, never
imported by the running application) and ``LicenseValidatorImpl`` (verifies -
only ever needs the public key embedded in ``domain/license.py``). Keeping
both sides of the format in one module guarantees they can never drift apart
into two subtly different canonicalizations.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from kingsec.domain.license import SIGNED_KEY_PREFIX, LicenseEdition

if TYPE_CHECKING:
    from kingsec.domain.license import License

_REQUIRED_PAYLOAD_FIELDS = (
    "license_id",
    "edition",
    "issued_to",
    "email",
    "issued_at",
    "expires_at",
    "max_users",
    "max_organizations",
    "features",
)


@dataclass(frozen=True)
class VerifiedLicenseKey:
    """The result of successfully parsing and verifying a KSL1 key."""

    payload: dict[str, Any]
    signature_b64: str


class InvalidLicenseKeyError(ValueError):
    """A license key string is malformed, or its signature doesn't verify.

    Distinct from plain ValueError (used elsewhere for "already activated"
    duplicates) so the web adapter can map the two to different, honest HTTP
    statuses instead of one generic catch-all.
    """


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def canonical_payload_bytes(payload: dict[str, Any]) -> bytes:
    """The exact bytes that get signed and, later, verified."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encode_license_key(payload: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    """Sign a payload and produce the full ``KSL1.`` key string. Issuer-side only."""
    payload_bytes = canonical_payload_bytes(payload)
    signature = private_key.sign(payload_bytes)
    return f"{SIGNED_KEY_PREFIX}{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"


def parse_and_verify_license_key(license_key: str, public_key_bytes: bytes) -> VerifiedLicenseKey:
    """Parse a ``KSL1.`` key and verify its signature.

    Returns the verified payload plus the raw signature (base64url, as
    stored verbatim in ``License.signature``). Raises
    ``InvalidLicenseKeyError`` for anything wrong: bad prefix,
    malformed base64/JSON, missing required fields, an unknown edition, or -
    most importantly - a signature that doesn't verify against the embedded
    public key. That last case is exactly what catches a typed-in garbage
    string or a hand-tampered payload.
    """
    if not license_key.startswith(SIGNED_KEY_PREFIX):
        raise InvalidLicenseKeyError("Not a signed license key")

    body = license_key[len(SIGNED_KEY_PREFIX) :]
    parts = body.split(".")
    if len(parts) != 2:
        raise InvalidLicenseKeyError("Malformed license key: expected KSL1.<payload>.<signature>")

    payload_b64, signature_b64 = parts
    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(signature_b64)
    except Exception as exc:
        raise InvalidLicenseKeyError(f"Malformed license key encoding: {exc}") from exc

    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        raise InvalidLicenseKeyError("License key signature does not verify") from None
    except Exception as exc:
        raise InvalidLicenseKeyError(f"Could not verify license key: {exc}") from exc

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise InvalidLicenseKeyError(f"License key payload is not valid JSON: {exc}") from exc

    missing = [f for f in _REQUIRED_PAYLOAD_FIELDS if f not in payload]
    if missing:
        raise InvalidLicenseKeyError(f"License key payload is missing required fields: {missing}")

    try:
        LicenseEdition(payload["edition"])
    except ValueError:
        raise InvalidLicenseKeyError(f"Unknown license edition: {payload['edition']!r}") from None

    return VerifiedLicenseKey(payload=payload, signature_b64=signature_b64)


def license_to_signed_payload(license: License) -> dict[str, Any]:
    """Reconstruct the exact payload shape that was originally signed, from
    a License's *current* stored fields.

    Used for at-rest verification: if anything in a signed field changed
    since activation (e.g. a hand-edited ``edition`` column), this
    reconstruction no longer matches what the issuer actually signed, and
    ``verify_stored_signature`` below correctly fails.
    """
    return {
        "license_id": str(license.id),
        "edition": license.edition.value,
        "issued_to": license.issued_to,
        "email": license.email,
        "issued_at": license.issued_at,
        "expires_at": license.expires_at,
        "max_users": license.max_users,
        "max_organizations": license.max_organizations,
        "features": sorted(license.features),
    }


def verify_stored_signature(payload: dict[str, Any], signature_b64: str, public_key_bytes: bytes) -> bool:
    """Does ``signature_b64`` verify against ``payload`` right now?"""
    if not signature_b64:
        return False
    try:
        signature = _b64url_decode(signature_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, canonical_payload_bytes(payload))
        return True
    except Exception:
        return False
