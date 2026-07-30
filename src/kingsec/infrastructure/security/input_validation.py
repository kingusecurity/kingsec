"""Security utilities: input validation, SSRF protection, sanitization."""

from __future__ import annotations

import ipaddress
import re
import urllib.parse

# ---------------------------------------------------------------------------
# Path traversal protection
# ---------------------------------------------------------------------------

_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def validate_identifier(value: str, label: str = "identifier") -> None:
    """Reject identifiers containing path traversal or special characters.

    Raises ``ValueError`` if the value contains characters outside the
    safe set ``[a-zA-Z0-9_-.]``.
    """
    if not value or not _SAFE_IDENTIFIER.match(value):
        raise ValueError(f"Invalid {label}: {value!r}")


def sanitize_path_component(value: str) -> str:
    """Strip path traversal sequences from a path component."""
    return value.replace("..", "").replace("/", "").replace("\\", "").strip()


def validate_backup_id(backup_id: str) -> None:
    """Validate a backup ID is safe for filesystem operations."""
    validate_identifier(backup_id, "backup_id")


def validate_plugin_id(plugin_id: str) -> None:
    """Validate a plugin ID is safe for filesystem operations."""
    validate_identifier(plugin_id, "plugin_id")


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_url_for_ssrf(url: str) -> None:
    """Validate a URL is not targeting private/internal networks.

    Raises ``ValueError`` if the URL targets a private IP, loopback,
    multicast, or reserved address.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"URL scheme must be http or https, got {parsed.scheme!r}")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL has no hostname")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is a domain name, not an IP — check for common internal names
        internal_names = {"localhost", "metadata.google.internal", "169.254.169.254"}
        if hostname.lower() in internal_names:
            raise ValueError(f"URL hostname resolves to internal service: {hostname!r}") from None
        return  # domain name — assume external

    if ip.is_loopback:
        raise ValueError(f"URL targets loopback address: {ip}")
    if ip.is_private:
        raise ValueError(f"URL targets private network: {ip}")
    if ip.is_multicast:
        raise ValueError(f"URL targets multicast address: {ip}")
    if ip.is_reserved:
        raise ValueError(f"URL targets reserved address: {ip}")
    if ip.is_link_local:
        raise ValueError(f"URL targets link-local address: {ip}")


# ---------------------------------------------------------------------------
# Input sanitization for SQL-like contexts
# ---------------------------------------------------------------------------

_DANGEROUS_SQL_PATTERNS = re.compile(
    r"(;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE)\s|--|/\*|\*/)",
    re.IGNORECASE,
)


def detect_sql_injection(value: str) -> bool:
    """Return True if the value looks like a SQL injection attempt.

    This is a heuristic check — parameterized queries are the primary
    defense. This catches obvious attempts.
    """
    return bool(_DANGEROUS_SQL_PATTERNS.search(value))


# ---------------------------------------------------------------------------
# XSS protection
# ---------------------------------------------------------------------------

_HTML_ESCAPE_TABLE = str.maketrans(
    {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#x27;"}
)


def escape_html(value: str) -> str:
    """Escape HTML special characters to prevent XSS."""
    return value.translate(_HTML_ESCAPE_TABLE)


# ---------------------------------------------------------------------------
# Filename sanitization
# ---------------------------------------------------------------------------

_UNSAFE_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def sanitize_filename(filename: str) -> str:
    """Remove or replace unsafe characters from a filename."""
    cleaned = _UNSAFE_FILENAME_CHARS.sub("_", filename)
    cleaned = cleaned.strip(". ")
    if not cleaned:
        cleaned = "unnamed"
    return cleaned[:255]  # max filename length
