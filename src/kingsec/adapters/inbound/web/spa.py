"""Serve the built frontend SPA from the same process as the API.

Registers, when the bundled frontend actually exists (``static/`` is
included in the packaged wheel per pyproject.toml, but is absent when
running from a source checkout with no frontend build):

- ``/assets/*`` -> Vite's content-hashed JS/CSS, long-lived immutable
  cache headers (the filename changes on content change, so a stale cache
  hit is impossible by construction).
- Everything else not matched by an earlier route (i.e. not
  ``/api/v1/*``, ``/docs``, etc.) -> a real static file at that path if
  one exists (favicon, manifest, service worker, ...), otherwise
  ``index.html`` so the client-side router can take over. Never
  aggressively cached - a stale ``index.html`` would keep pointing at
  assets from a previous deploy.

Must be registered after every other route so the catch-all only ever
sees paths nothing more specific claimed first.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

_ASSET_CACHE_CONTROL = "public, max-age=31536000, immutable"
_NO_CACHE = "no-cache"

# Reserved top-level segments that must 404 on a genuine miss rather than
# fall back to index.html - an API client hitting a typo'd endpoint needs
# a real 404, not a 200 full of HTML it didn't ask for.
_RESERVED_FIRST_SEGMENTS = frozenset({"api", "docs", "redoc", "openapi.json"})


def _is_reserved_path(full_path: str) -> bool:
    return full_path.split("/", 1)[0] in _RESERVED_FIRST_SEGMENTS


class _ImmutableStaticFiles(StaticFiles):
    """StaticFiles that marks every response long-lived + immutable.

    Safe only because Vite content-hashes these filenames - the same URL
    never resolves to different content, so telling browsers/CDNs to
    never revalidate is correct, not just fast.
    """

    async def get_response(self, path: str, scope: Scope) -> Response:
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = _ASSET_CACHE_CONTROL
        return response


def register_spa(app: FastAPI, *, static_dir: Path | None = None) -> None:
    """Mount the built frontend, if one is bundled.

    Args:
        app: The FastAPI app to register routes on. Call this after every
            other route/router has been added - the fallback route below
            is a catch-all and must be last to avoid shadowing anything.
        static_dir: Override for tests. Defaults to the ``static/``
            directory bundled alongside this module.
    """
    static_dir = static_dir or (Path(__file__).parent / "static")
    index_file = static_dir / "index.html"
    assets_dir = static_dir / "assets"

    if not index_file.is_file():
        return

    if assets_dir.is_dir():
        app.mount("/assets", _ImmutableStaticFiles(directory=assets_dir), name="spa-assets")

    @app.get("/", include_in_schema=False)
    async def spa_index() -> FileResponse:
        return FileResponse(index_file, headers={"Cache-Control": _NO_CACHE})

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str) -> FileResponse:
        # A miss under a reserved prefix (api/, docs, redoc, openapi.json)
        # means the specific route for it doesn't exist - a real 404, not
        # the SPA shell. Only reachable here because Starlette tries every
        # registered route in order and none of the real API/doc routes
        # matched this exact path.
        if _is_reserved_path(full_path):
            raise HTTPException(status_code=404)

        # Resolve-and-check-prefix guards against path traversal (e.g.
        # "../../etc/passwd") escaping static_dir via ".." segments.
        candidate = (static_dir / full_path).resolve()
        if candidate.is_file() and candidate.is_relative_to(static_dir.resolve()):
            return FileResponse(candidate, headers={"Cache-Control": _NO_CACHE})
        return FileResponse(index_file, headers={"Cache-Control": _NO_CACHE})
