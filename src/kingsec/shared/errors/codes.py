"""The central catalog of stable error codes.

Why a central catalog?
    An error code is part of your product's *contract*. Support scripts, log
    dashboards, runbooks, and API clients all key off it. The human-readable
    message may be reworded a hundred times, but ``KS-AUTHZ-001`` must mean the
    same thing forever. Keeping every code in one file makes the whole set
    reviewable at a glance and makes accidental duplication obvious.

Code scheme: ``KS-<DOMAIN>-<NNN>``
    KS      - product namespace (KingSec), so codes never collide with a
              dependency's codes in aggregated logs.
    DOMAIN  - a short subsystem tag (CFG, VAL, AUTHZ, ...).
    NNN     - a zero-padded sequence within that subsystem, leaving room to grow.

These are plain string constants (not an Enum) on purpose: they are used as
class attributes and compared as strings everywhere, so the extra machinery of
an Enum would buy nothing here while adding ceremony.
"""

from __future__ import annotations


class ErrorCode:
    """Namespace of stable error-code constants. Do not renumber existing codes."""

    UNEXPECTED = "KS-ERR-000"          # the catch-all base; something unforeseen
    CONFIGURATION = "KS-CFG-001"       # invalid or missing configuration
    VALIDATION = "KS-VAL-001"          # caller-supplied input failed validation
    AUTHORIZATION = "KS-AUTHZ-001"     # action not permitted / not authorized
    NOT_FOUND = "KS-RES-001"           # a requested resource does not exist
    EXTERNAL_SERVICE = "KS-EXT-001"    # a downstream/external dependency failed
    EXTERNAL_TIMEOUT = "KS-EXT-002"    # a downstream/external dependency timed out
    SCANNER = "KS-SCAN-001"            # a scan/plugin could not complete
    PERSISTENCE = "KS-STORE-001"       # a storage/persistence operation failed
