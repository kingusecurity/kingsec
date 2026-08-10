#!/usr/bin/env python
"""Issue a real, signed KingSec license key.

Run by hand by whoever holds the signing private key (see keys/README.md).
Never imported by the running application - this script is the only place
in the whole codebase that touches the private key.

Usage:
    python tools/issue_license.py \\
        --private-key keys/license_signing_key.pem \\
        --edition professional \\
        --issued-to "Acme Corp" \\
        --email admin@acme.com \\
        --expires-at 2027-08-01

    # Perpetual (no expiry), with negotiated limit overrides and an add-on feature:
    python tools/issue_license.py \\
        --private-key keys/license_signing_key.pem \\
        --edition enterprise \\
        --issued-to "Acme Corp" \\
        --email admin@acme.com \\
        --max-users 250 \\
        --feature custom_sla

Prints one line: the full ``KSL1.<payload>.<signature>`` key string, ready
to hand to the customer and paste into the License page's Activate box.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

# Allow running directly from a source checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kingsec.application.services.license_key_codec import encode_license_key
from kingsec.domain.license import LicenseEdition


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--private-key",
        required=True,
        type=Path,
        help="Path to the Ed25519 private key PEM file (never committed - see keys/README.md).",
    )
    parser.add_argument(
        "--edition",
        required=True,
        choices=[e.value for e in LicenseEdition],
        help="License edition to grant.",
    )
    parser.add_argument("--issued-to", required=True, help="Customer/organization name.")
    parser.add_argument("--email", default="", help="Customer contact email.")
    parser.add_argument(
        "--expires-at",
        default="",
        help="ISO date (YYYY-MM-DD) the license expires. Omit for a perpetual license.",
    )
    parser.add_argument(
        "--max-users",
        type=int,
        default=None,
        help="Override this specific license's user limit (default: the edition's own limit).",
    )
    parser.add_argument(
        "--max-organizations",
        type=int,
        default=None,
        help="Override this specific license's organization limit (default: the edition's own limit).",
    )
    parser.add_argument(
        "--feature",
        action="append",
        dest="features",
        default=[],
        help="An additional feature to grant on top of the edition's stock features. Repeatable.",
    )
    parser.add_argument(
        "--license-id",
        default="",
        help="Override the generated license ID (rarely needed - e.g. re-issuing under a known ID).",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    if not args.private_key.is_file():
        print(f"error: private key file not found: {args.private_key}", file=sys.stderr)
        return 1

    private_key_bytes = args.private_key.read_bytes()
    try:
        loaded_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except Exception as exc:
        print(f"error: could not load private key: {exc}", file=sys.stderr)
        return 1

    if not isinstance(loaded_key, Ed25519PrivateKey):
        print(f"error: {args.private_key} is not an Ed25519 private key", file=sys.stderr)
        return 1
    private_key = loaded_key

    payload = {
        "license_id": args.license_id or f"lic-{uuid.uuid4().hex}",
        "edition": args.edition,
        "issued_to": args.issued_to,
        "email": args.email,
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": args.expires_at,
        "max_users": args.max_users,
        "max_organizations": args.max_organizations,
        "features": sorted(set(args.features)),
    }

    license_key = encode_license_key(payload, private_key)

    print(license_key)
    print(f"\n(issued: edition={args.edition}, issued_to={args.issued_to!r}, "
          f"expires_at={args.expires_at or 'never'}, license_id={payload['license_id']})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
