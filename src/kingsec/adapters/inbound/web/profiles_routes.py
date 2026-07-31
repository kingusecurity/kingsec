"""Assessment profiles routes — thin adapter.

Bridges the existing profiles router from ``interfaces.api.routes.profiles``
into the web adapter's ``/api/v1`` prefix convention and auth dependency.
"""

from __future__ import annotations

from fastapi import APIRouter

from .auth import get_current_user

from kingsec.interfaces.api.routes.profiles import create_profiles_router

router = APIRouter(prefix="/api/v1")
router.include_router(create_profiles_router(get_current_user=get_current_user))
