"""Enterprise plugin package domain — pure domain, no framework dependencies.

Covers: PluginPackage, PluginVersion, PluginDependency, PluginCompatibility,
PluginManifest, PluginSignature, PluginHealth, PluginInstallStatus.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import total_ordering


class PluginInstallStatus(StrEnum):
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED = "installed"
    ENABLED = "enabled"
    DISABLED = "disabled"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class PluginHealth(StrEnum):
    UNKNOWN = "unknown"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


@total_ordering
@dataclass(frozen=True)
class PluginVersion:
    """Semantic version value object."""

    major: int
    minor: int
    patch: int

    @staticmethod
    def parse(version_str: str) -> PluginVersion:
        parts = version_str.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version string: {version_str}")
        return PluginVersion(
            major=int(parts[0]),
            minor=int(parts[1]),
            patch=int(parts[2]),
        )

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, PluginVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PluginVersion):
            return NotImplemented
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)

    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch))

    def satisfies(self, constraint: str) -> bool:
        if constraint.startswith(">="):
            min_v = PluginVersion.parse(constraint[2:])
            return self >= min_v
        if constraint.startswith("<="):
            max_v = PluginVersion.parse(constraint[2:])
            return self <= max_v
        if constraint.startswith(">"):
            min_v = PluginVersion.parse(constraint[1:])
            return self > min_v
        if constraint.startswith("<"):
            max_v = PluginVersion.parse(constraint[1:])
            return self < max_v
        if constraint.startswith("=="):
            expected = PluginVersion.parse(constraint[2:])
            return self == expected
        if constraint.startswith("^"):
            expected = PluginVersion.parse(constraint[1:])
            return self.major == expected.major and self >= expected
        if constraint.startswith("~"):
            expected = PluginVersion.parse(constraint[1:])
            return (self.major, self.minor) == (expected.major, expected.minor) and self >= expected
        if constraint == "*":
            return True
        return self == PluginVersion.parse(constraint)


@dataclass(frozen=True)
class PluginDependency:
    plugin_id: str
    version_constraint: str


@dataclass(frozen=True)
class PluginCompatibility:
    min_api_version: str
    max_api_version: str
    platforms: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginSignature:
    algorithm: str
    value: str
    public_key_fingerprint: str


@dataclass(frozen=True)
class PluginManifest:
    id: str
    name: str
    version: PluginVersion
    description: str = ""
    author: str = ""
    license: str = ""
    dependencies: tuple[PluginDependency, ...] = ()
    compatibility: PluginCompatibility | None = None
    checksum_sha256: str = ""
    signature: PluginSignature | None = None
    entry_point: str = ""
    homepage: str = ""
    repository: str = ""
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class PluginPackage:
    id: str
    manifest: PluginManifest
    status: PluginInstallStatus
    installed_version: PluginVersion | None = None
    install_path: str = ""
    installed_at: str = ""
    updated_at: str = ""
    health: PluginHealth = PluginHealth.UNKNOWN
    error_message: str = ""
    size_bytes: int = 0
    checksum_verified: bool = False
    signature_verified: bool = False
