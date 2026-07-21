from __future__ import annotations

from kingsec.domain.plugin_package import (
    PluginCompatibility,
    PluginDependency,
    PluginHealth,
    PluginInstallStatus,
    PluginManifest,
    PluginPackage,
    PluginSignature,
    PluginVersion,
)


class TestPluginVersion:
    def test_parse_valid(self) -> None:
        v = PluginVersion.parse("1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3

    def test_parse_invalid(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            PluginVersion.parse("1.2")

    def test_str(self) -> None:
        assert str(PluginVersion(2, 0, 1)) == "2.0.1"

    def test_comparison(self) -> None:
        v1 = PluginVersion(1, 0, 0)
        v2 = PluginVersion(2, 0, 0)
        assert v1 < v2
        assert v2 > v1
        assert v1 == PluginVersion(1, 0, 0)

    def test_satisfies_exact(self) -> None:
        v = PluginVersion(1, 5, 0)
        assert v.satisfies("1.5.0")
        assert not v.satisfies("1.6.0")

    def test_satisfies_range(self) -> None:
        v = PluginVersion(2, 0, 0)
        assert v.satisfies(">=1.0.0")
        assert v.satisfies("<=3.0.0")
        assert not v.satisfies(">=3.0.0")

    def test_satisfies_caret(self) -> None:
        v = PluginVersion(2, 3, 0)
        assert v.satisfies("^2.0.0")
        assert not v.satisfies("^3.0.0")

    def test_satisfies_tilde(self) -> None:
        v = PluginVersion(2, 3, 1)
        assert v.satisfies("~2.3.0")
        assert not v.satisfies("~2.4.0")

    def test_satisfies_wildcard(self) -> None:
        v = PluginVersion(9, 9, 9)
        assert v.satisfies("*")

    def test_hashable(self) -> None:
        s = {PluginVersion(1, 0, 0), PluginVersion(1, 0, 0)}
        assert len(s) == 1


class TestPluginManifest:
    def test_create_minimal(self) -> None:
        m = PluginManifest(id="p1", name="TestPlugin", version=PluginVersion(1, 0, 0))
        assert m.id == "p1"
        assert m.name == "TestPlugin"
        assert str(m.version) == "1.0.0"

    def test_create_with_all_fields(self) -> None:
        m = PluginManifest(
            id="p1",
            name="FullPlugin",
            version=PluginVersion(2, 0, 0),
            description="A test plugin",
            author="KingSec",
            license="MIT",
            dependencies=(PluginDependency("core", ">=1.0.0"),),
            compatibility=PluginCompatibility(min_api_version="1.0.0", max_api_version="2.0.0"),
            checksum_sha256="abc123",
            signature=PluginSignature(algorithm="SHA256", value="sig", public_key_fingerprint="fp"),
            entry_point="main.py",
            homepage="https://example.com",
            repository="https://github.com/example",
            tags=("security", "scanner"),
        )
        assert m.dependencies[0].plugin_id == "core"


class TestPluginPackage:
    def test_create_default(self) -> None:
        manifest = PluginManifest(id="p1", name="Test", version=PluginVersion(1, 0, 0))
        pkg = PluginPackage(id="p1", manifest=manifest, status=PluginInstallStatus.INSTALLED)
        assert pkg.status == PluginInstallStatus.INSTALLED
        assert pkg.health == PluginHealth.UNKNOWN

    def test_frozen(self) -> None:
        manifest = PluginManifest(id="p1", name="Test", version=PluginVersion(1, 0, 0))
        pkg = PluginPackage(id="p1", manifest=manifest, status=PluginInstallStatus.ENABLED)
        import pytest

        with pytest.raises(AttributeError):
            pkg.status = PluginInstallStatus.DISABLED  # type: ignore

    def test_equality(self) -> None:
        manifest = PluginManifest(id="p1", name="Test", version=PluginVersion(1, 0, 0))
        p1 = PluginPackage(id="p1", manifest=manifest, status=PluginInstallStatus.INSTALLED)
        p2 = PluginPackage(id="p1", manifest=manifest, status=PluginInstallStatus.INSTALLED)
        assert p1 == p2


class TestPluginInstallStatus:
    def test_enum_values(self) -> None:
        assert PluginInstallStatus.NOT_INSTALLED.value == "not_installed"
        assert PluginInstallStatus.INSTALLING.value == "installing"
        assert PluginInstallStatus.INSTALLED.value == "installed"
        assert PluginInstallStatus.ENABLED.value == "enabled"
        assert PluginInstallStatus.DISABLED.value == "disabled"
        assert PluginInstallStatus.FAILED.value == "failed"
        assert PluginInstallStatus.ROLLED_BACK.value == "rolled_back"
