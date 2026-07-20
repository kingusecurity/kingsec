from __future__ import annotations

from abc import ABC, abstractmethod

from kingsec.domain.plugin_package import PluginManifest, PluginSignature


class PluginValidatorPort(ABC):
    """Validation logic for plugin packages and manifests."""

    @abstractmethod
    def validate_manifest(self, manifest_data: dict) -> PluginManifest:
        """Parse and validate raw manifest dict into domain object. Raises on failure."""
        ...

    @abstractmethod
    def validate_checksum(self, package_path: str, expected_sha256: str) -> bool:
        """Verify SHA-256 checksum of plugin archive."""
        ...

    @abstractmethod
    def validate_signature(self, package_path: str, signature: PluginSignature) -> bool:
        """Verify cryptographic signature of plugin archive."""
        ...

    @abstractmethod
    def validate_compatibility(self, manifest: PluginManifest) -> bool:
        """Check plugin is compatible with current KingSec API version."""
        ...

    @abstractmethod
    def validate_dependencies(
        self, manifest: PluginManifest, installed: list[PluginManifest],
    ) -> list[str]:
        """Check all dependency constraints are met. Returns list of missing plugin IDs."""
        ...
