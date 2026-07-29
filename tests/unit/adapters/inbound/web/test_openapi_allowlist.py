"""Structural test: OpenAPI unauthenticated route allowlist.

Every operation with security=None in the shipped OpenAPI spec must be
explicitly listed. Adding a new public route requires an entry here.
"""

from __future__ import annotations

from fastapi import FastAPI

from kingsec.adapters.inbound.web.openapi import configure_openapi
from kingsec.adapters.inbound.web.versioning import register_versioned_routes
from kingsec.infrastructure.config.models import AppSettings

# Committed allowlist — only these may lack authentication in the OpenAPI spec.
ALLOWED_PUBLIC: set[tuple[str, str]] = {
    ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/register"),
    ("POST", "/api/v1/auth/refresh"),
    ("GET", "/api/v1/healthz/live"),
    ("GET", "/api/v1/healthz/ready"),
    ("GET", "/api/v1/health"),
    ("POST", "/api/v1/mfa/verify"),
    ("POST", "/api/v1/mfa/recovery"),
    ("POST", "/api/v1/sessions/refresh"),
    ("GET", "/api/v1/plugin-sdk/permissions"),
}


def _public_operations() -> set[tuple[str, str]]:
    """Return HTTP method + path for every operation with security=None."""
    app = FastAPI()
    register_versioned_routes(app)
    configure_openapi(app, AppSettings())
    spec = app.openapi()
    public: set[tuple[str, str]] = set()
    for path, methods in spec.get("paths", {}).items():
        for method in ("get", "post", "put", "patch", "delete", "options", "head"):
            op = methods.get(method)
            if op is None:
                continue
            sec = op.get("security")
            if sec is None:
                public.add((method.upper(), path))
    return public


class TestOpenAPIPublicRouteAllowlist:
    def test_public_routes_match_allowlist(self) -> None:
        actual = _public_operations()
        missing = ALLOWED_PUBLIC - actual
        extra = actual - ALLOWED_PUBLIC
        assert not extra, f"Extra public routes (not in allowlist): {extra}"
        assert not missing, f"Allowlisted routes missing from spec: {missing}"
