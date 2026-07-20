"""RFC 6238 TOTP implementation — no external dependencies.

Uses only stdlib (hmac, hashlib, struct, time, os) for compatibility
with Google Authenticator, Microsoft Authenticator, Authy, etc.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

from kingsec.application.ports.outbound.totp_service import TotpServicePort


class TotpService(TotpServicePort):
    """TOTP implementation per RFC 6238 with configurable clock drift."""

    _STEP: int = 30

    def generate_secret(self) -> str:
        """Generate a random 160-bit (20-byte) Base32 secret."""
        raw = os.urandom(20)
        return base64.b32encode(raw).decode("ascii").rstrip("=")

    def generate_uri(self, secret: str, username: str, issuer: str = "KingSec") -> str:
        """Generate ``otpauth://`` URI for QR code provisioning."""
        params = f"secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period={self._STEP}"
        return f"otpauth://totp/{quote(issuer)}:{quote(username)}?{params}"

    def verify(self, secret: str, code: str, drift: int = 1) -> bool:
        """Verify a TOTP code with allowable clock drift (default ±1 step)."""
        if not code.isdigit() or len(code) != 6:
            return False
        now = int(time.time())
        for offset in range(-drift, drift + 1):
            expected = self._generate_code(secret, now + offset * self._STEP)
            if hmac.compare_digest(expected, code):
                return True
        return False

    def _generate_code(self, secret: str, timestamp: int) -> str:
        """Generate a single 6-digit TOTP code for a given timestamp."""
        key = base64.b32decode(secret, casefold=True)
        counter = struct.pack(">Q", timestamp // self._STEP)
        mac = hmac.new(key, counter, hashlib.sha1).digest()
        offset = mac[-1] & 0x0F
        truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
        return f"{truncated % 1_000_000:06d}"
