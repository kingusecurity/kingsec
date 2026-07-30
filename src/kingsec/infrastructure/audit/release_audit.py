"""Release audit service.

Tracks release history, deployment metadata, and audit trail
for compliance and troubleshooting.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ReleaseEntry:
    """A single release record."""

    version: str
    released_at: str
    release_type: str  # major, minor, patch, hotfix
    changes: tuple[str, ...] = ()
    breaking_changes: tuple[str, ...] = ()
    upgrade_from: str | None = None
    upgraded_at: str | None = None
    upgraded_by: str | None = None
    notes: str = ""


@dataclass(frozen=True)
class ReleaseAuditReport:
    """Complete release audit trail."""

    current_version: str
    installed_at: str
    total_releases: int
    releases: tuple[ReleaseEntry, ...]
    upgrade_history: tuple[ReleaseEntry, ...]


class ReleaseAuditService:
    """Manages release history and audit trail."""

    def __init__(self, data_dir: Path) -> None:
        self._data_dir = data_dir
        self._releases_file = data_dir / "releases.json"

    def _load_releases(self) -> list[ReleaseEntry]:
        if not self._releases_file.is_file():
            return []
        try:
            data = json.loads(self._releases_file.read_text(encoding="utf-8"))
            return [ReleaseEntry(**r) for r in data.get("releases", [])]
        except (json.JSONDecodeError, TypeError, KeyError):
            return []

    def _save_releases(self, releases: list[ReleaseEntry]) -> None:
        data = {"releases": [asdict(r) for r in releases]}
        self._releases_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def record_release(
        self,
        version: str,
        release_type: str = "patch",
        changes: tuple[str, ...] = (),
        breaking_changes: tuple[str, ...] = (),
        notes: str = "",
    ) -> ReleaseEntry:
        """Record a new release."""
        entry = ReleaseEntry(
            version=version,
            released_at=datetime.datetime.now(datetime.UTC).isoformat(),
            release_type=release_type,
            changes=changes,
            breaking_changes=breaking_changes,
            notes=notes,
        )

        releases = self._load_releases()
        releases.append(entry)
        self._save_releases(releases)
        return entry

    def record_upgrade(
        self,
        from_version: str,
        to_version: str,
        upgraded_by: str = "system",
    ) -> ReleaseEntry:
        """Record an upgrade event."""
        entry = ReleaseEntry(
            version=to_version,
            released_at=datetime.datetime.now(datetime.UTC).isoformat(),
            release_type="upgrade",
            upgrade_from=from_version,
            upgraded_at=datetime.datetime.now(datetime.UTC).isoformat(),
            upgraded_by=upgraded_by,
        )

        releases = self._load_releases()
        releases.append(entry)
        self._save_releases(releases)
        return entry

    def get_current_version(self) -> str | None:
        """Get the currently installed version."""
        version_file = self._data_dir / ".kingsec-version"
        if version_file.is_file():
            return version_file.read_text(encoding="utf-8").strip()
        return None

    def set_current_version(self, version: str) -> None:
        """Set the currently installed version."""
        version_file = self._data_dir / ".kingsec-version"
        version_file.write_text(version, encoding="utf-8")

    def generate_report(self) -> ReleaseAuditReport:
        """Generate a complete release audit report."""
        releases = self._load_releases()
        current = self.get_current_version() or "unknown"
        installed_at = releases[0].released_at if releases else "unknown"
        upgrade_history = tuple(r for r in releases if r.release_type == "upgrade")

        return ReleaseAuditReport(
            current_version=current,
            installed_at=installed_at,
            total_releases=len(releases),
            releases=tuple(releases),
            upgrade_history=upgrade_history,
        )

    def get_version_changelog(self, version: str) -> ReleaseEntry | None:
        """Get the release entry for a specific version."""
        releases = self._load_releases()
        for release in releases:
            if release.version == version:
                return release
        return None
