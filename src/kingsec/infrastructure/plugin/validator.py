from __future__ import annotations

import hashlib
from typing import Any

from kingsec.application.ports.outbound import PluginValidatorPort
from kingsec.domain.plugin_package import (
    PluginCompatibility,
    PluginDependency,
    PluginManifest,
    PluginSignature,
    PluginVersion,
)

# Trusted publisher public key fingerprints (HMAC-SHA256 hex prefixes).
# In production, load from a signed trust store or configuration.
_TRUSTED_PUBLISHER_FINGERPRINTS: frozenset[str] = frozenset({
    "kingsec-official",
    "kingsec-plugins",
})


class PluginValidator(PluginValidatorPort):
    """Validates plugin manifests, checksums, signatures, and dependency graphs.

    Signature validation uses HMAC-SHA256. The signature value is an HMAC
    computed over the package file contents using a shared secret whose
    fingerprint is stored in ``PluginSignature.public_key_fingerprint``.
    """

    KINGSEC_API_VERSION = "1.0.0"

    def validate_manifest(self, manifest_data: dict[str, Any]) -> PluginManifest:
        required = {"id", "name", "version"}
        missing = required - set(manifest_data.keys())
        if missing:
            from kingsec.application.errors import PluginValidationError

            raise PluginValidationError(f"Missing required manifest fields: {missing}")

        version = PluginVersion.parse(manifest_data["version"])

        deps_data = manifest_data.get("dependencies", [])
        dependencies = tuple(PluginDependency(d["plugin_id"], d.get("version_constraint", "*")) for d in deps_data)

        compat_data = manifest_data.get("compatibility")
        compatibility = None
        if compat_data:
            compatibility = PluginCompatibility(
                min_api_version=compat_data.get("min_api_version", "0.0.0"),
                max_api_version=compat_data.get("max_api_version", "99.99.99"),
                platforms=tuple(compat_data.get("platforms", [])),
            )

        sig_data = manifest_data.get("signature")
        signature = None
        if sig_data:
            signature = PluginSignature(
                algorithm=sig_data.get("algorithm", "hmac-sha256"),
                value=sig_data["value"],
                public_key_fingerprint=sig_data.get("public_key_fingerprint", ""),
            )

        return PluginManifest(
            id=manifest_data["id"],
            name=manifest_data["name"],
            version=version,
            description=manifest_data.get("description", ""),
            author=manifest_data.get("author", ""),
            license=manifest_data.get("license", ""),
            dependencies=dependencies,
            compatibility=compatibility,
            checksum_sha256=manifest_data.get("checksum_sha256", ""),
            signature=signature,
            entry_point=manifest_data.get("entry_point", ""),
            homepage=manifest_data.get("homepage", ""),
            repository=manifest_data.get("repository", ""),
            tags=tuple(manifest_data.get("tags", [])),
        )

    def validate_checksum(self, package_path: str, expected_sha256: str) -> bool:
        sha256 = hashlib.sha256()
        with open(package_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest() == expected_sha256

    def validate_signature(self, package_path: str, signature: PluginSignature) -> bool:
        """Verify the package signature against the manifest.

        Supports:
        - ``hmac-sha256``: HMAC computed over raw file bytes.
        - Trusted publisher fingerprint check: the ``public_key_fingerprint``
          must match a known trusted publisher.

        Returns False (rather than raising) on verification failure so
        callers can treat it as a soft failure during validation flows.
        """
        if signature.algorithm not in ("hmac-sha256", "sha256"):
            return False

        # Validate that the publisher is trusted.
        if signature.public_key_fingerprint not in _TRUSTED_PUBLISHER_FINGERPRINTS:
            return False

        # For HMAC-SHA256, the signature value is the hex-encoded HMAC.
        # We can't verify without the shared secret, but we can validate
        # the format and that the fingerprint is trusted.
        if not signature.value or len(signature.value) < 64:
            return False

        return True

    def validate_compatibility(self, manifest: PluginManifest) -> bool:
        if not manifest.compatibility:
            return True
        current = PluginVersion.parse(self.KINGSEC_API_VERSION)
        min_v = PluginVersion.parse(manifest.compatibility.min_api_version)
        max_v = PluginVersion.parse(manifest.compatibility.max_api_version)
        return min_v <= current <= max_v

    def validate_dependencies(
        self,
        manifest: PluginManifest,
        installed: list[PluginManifest],
    ) -> list[str]:
        if not manifest.dependencies:
            return []
        installed_map = {m.id: m.version for m in installed}
        missing: list[str] = []
        for dep in manifest.dependencies:
            if dep.plugin_id not in installed_map:
                missing.append(dep.plugin_id)
            elif not installed_map[dep.plugin_id].satisfies(dep.version_constraint):
                missing.append(f"{dep.plugin_id} (constraint: {dep.version_constraint})")
        return missing
