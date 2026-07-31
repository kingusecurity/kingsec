"""Scanner discovery routes — thin adapter.

Bridges the existing scanner discovery router from
``interfaces.api.routes.scanner_discovery`` into the web adapter's
``/api/v1`` prefix convention and auth dependency.
"""

from __future__ import annotations

from fastapi import APIRouter

from .auth import get_current_user

from kingsec.interfaces.api.routes.scanner_discovery import create_scanner_discovery_router

router = APIRouter(prefix="/api/v1")
router.include_router(create_scanner_discovery_router(get_current_user=get_current_user))
