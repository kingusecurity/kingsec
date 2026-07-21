from __future__ import annotations

import os
import tempfile

import pytest

from kingsec.application.errors import PluginValidationError
from kingsec.domain.plugin_package import (
    PluginCompatibility,
    PluginDependency,
    PluginManifest,
    PluginVersion,
)
from kingsec.infrastructure.plugin.validator import PluginValidator


class TestPluginValidator:
    def setup_method(self) -> None:
        self.validator = PluginValidator()

    def test_validate_manifest_valid(self) -> None:
        data = {"id": "p1", "name": "Test", "version": "1.0.0"}
        m = self.validator.validate_manifest(data)
        assert m.id == "p1"
        assert m.name == "Test"
        assert str(m.version) == "1.0.0"

    def test_validate_manifest_missing_fields(self) -> None:
        with pytest.raises(PluginValidationError):
            self.validator.validate_manifest({"id": "p1"})

    def test_validate_manifest_with_all_fields(self) -> None:
        data = {
            "id": "p1",
            "name": "Test",
            "version": "2.0.0",
            "description": "desc",
            "author": "auth",
            "license": "MIT",
            "entry_point": "main.py",
            "homepage": "https://example.com",
            "repository": "https://github.com/example",
            "tags": ["security"],
            "checksum_sha256": "abc123",
            "dependencies": [{"plugin_id": "core", "version_constraint": ">=1.0.0"}],
            "compatibility": {"min_api_version": "1.0.0", "max_api_version": "2.0.0", "platforms": ["linux"]},
            "signature": {"algorithm": "SHA256", "value": "sigvalue", "public_key_fingerprint": "fp123"},
        }
        m = self.validator.validate_manifest(data)
        assert len(m.dependencies) == 1
        assert m.dependencies[0].plugin_id == "core"
        assert m.compatibility is not None
        assert m.compatibility.min_api_version == "1.0.0"
        assert m.signature is not None
        assert m.signature.algorithm == "SHA256"

    def test_validate_checksum(self) -> None:
        import hashlib
        fd, path = tempfile.mkstemp()
        content = b"test data for checksum"
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        expected = hashlib.sha256(content).hexdigest()
        try:
            assert self.validator.validate_checksum(path, expected) is True
            assert self.validator.validate_checksum(path, "0" * 64) is False
        finally:
            os.unlink(path)

    def test_validate_compatibility_default(self) -> None:
        m = PluginManifest(id="p1", name="Test", version=PluginVersion(1, 0, 0))
        assert self.validator.validate_compatibility(m) is True

    def test_validate_compatibility_compatible(self) -> None:
        m = PluginManifest(
            id="p1", name="Test", version=PluginVersion(1, 0, 0),
            compatibility=PluginCompatibility(min_api_version="0.5.0", max_api_version="2.0.0"),
        )
        assert self.validator.validate_compatibility(m) is True

    def test_validate_compatibility_incompatible(self) -> None:
        m = PluginManifest(
            id="p1", name="Test", version=PluginVersion(1, 0, 0),
            compatibility=PluginCompatibility(min_api_version="2.0.0", max_api_version="3.0.0"),
        )
        assert self.validator.validate_compatibility(m) is False

    def test_validate_dependencies_empty(self) -> None:
        m = PluginManifest(id="p1", name="Test", version=PluginVersion(1, 0, 0))
        assert self.validator.validate_dependencies(m, []) == []

    def test_validate_dependencies_met(self) -> None:
        m = PluginManifest(
            id="p1", name="Test", version=PluginVersion(1, 0, 0),
            dependencies=(PluginDependency("core", ">=1.0.0"),),
        )
        core = PluginManifest(id="core", name="Core", version=PluginVersion(1, 5, 0))
        assert self.validator.validate_dependencies(m, [core]) == []

    def test_validate_dependencies_missing(self) -> None:
        m = PluginManifest(
            id="p1", name="Test", version=PluginVersion(1, 0, 0),
            dependencies=(PluginDependency("missing", ">=1.0.0"),),
        )
        missing = self.validator.validate_dependencies(m, [])
        assert "missing" in missing[0]

    def test_validate_dependencies_version_mismatch(self) -> None:
        m = PluginManifest(
            id="p1", name="Test", version=PluginVersion(1, 0, 0),
            dependencies=(PluginDependency("core", ">=2.0.0"),),
        )
        core = PluginManifest(id="core", name="Core", version=PluginVersion(1, 0, 0))
        missing = self.validator.validate_dependencies(m, [core])
        assert len(missing) == 1
        assert "core" in missing[0]
