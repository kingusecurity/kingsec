from __future__ import annotations

from kingsec.application.ports.outbound import (
    PluginInstallerPort,
    PluginMarketplacePort,
    PluginRepositoryPort,
    PluginValidatorPort,
)
from kingsec.domain.plugin_package import (
    PluginHealth,
    PluginInstallStatus,
    PluginManifest,
    PluginPackage,
)


class InstallPlugin:
    def __init__(
        self,
        repo: PluginRepositoryPort,
        installer: PluginInstallerPort,
        validator: PluginValidatorPort,
    ) -> None:
        self._repo = repo
        self._installer = installer
        self._validator = validator

    def execute(self, package_path: str, manifest: PluginManifest) -> PluginPackage:
        existing = self._repo.find_by_id(manifest.id)
        if existing and existing.status in (PluginInstallStatus.INSTALLED, PluginInstallStatus.ENABLED, PluginInstallStatus.DISABLED):
            raise ValueError(f"Plugin '{manifest.id}' is already installed")

        incompat = self._validator.validate_dependencies(manifest, [])
        if incompat:
            from kingsec.application.errors import PluginDependencyError
            raise PluginDependencyError(f"Unmet dependencies: {incompat}")

        install_path = self._installer.install(package_path, manifest)
        plugin = PluginPackage(
            id=manifest.id,
            manifest=manifest,
            status=PluginInstallStatus.INSTALLED,
            installed_version=manifest.version,
            install_path=install_path,
            checksum_verified=bool(manifest.checksum_sha256),
            signature_verified=manifest.signature is not None,
            size_bytes=0,
            health=PluginHealth.HEALTHY,
        )
        self._repo.save(plugin)
        return plugin


class UninstallPlugin:
    def __init__(self, repo: PluginRepositoryPort, installer: PluginInstallerPort) -> None:
        self._repo = repo
        self._installer = installer

    def execute(self, plugin_id: str) -> None:
        plugin = self._repo.find_by_id(plugin_id)
        if not plugin:
            from kingsec.application.errors import PluginNotFoundError
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")
        self._installer.uninstall(plugin_id)
        self._repo.delete(plugin_id)


class EnablePlugin:
    def __init__(self, repo: PluginRepositoryPort) -> None:
        self._repo = repo

    def execute(self, plugin_id: str) -> PluginPackage:
        plugin = self._repo.find_by_id(plugin_id)
        if not plugin:
            from kingsec.application.errors import PluginNotFoundError
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")
        self._repo.update_status(plugin_id, PluginInstallStatus.ENABLED)
        updated = self._repo.find_by_id(plugin_id)
        assert updated is not None
        return updated


class DisablePlugin:
    def __init__(self, repo: PluginRepositoryPort) -> None:
        self._repo = repo

    def execute(self, plugin_id: str) -> PluginPackage:
        plugin = self._repo.find_by_id(plugin_id)
        if not plugin:
            from kingsec.application.errors import PluginNotFoundError
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")
        self._repo.update_status(plugin_id, PluginInstallStatus.DISABLED)
        updated = self._repo.find_by_id(plugin_id)
        assert updated is not None
        return updated


class UpdatePlugin:
    def __init__(
        self,
        repo: PluginRepositoryPort,
        installer: PluginInstallerPort,
        validator: PluginValidatorPort,
    ) -> None:
        self._repo = repo
        self._installer = installer
        self._validator = validator

    def execute(self, plugin_id: str, package_path: str, manifest: PluginManifest) -> PluginPackage:
        existing = self._repo.find_by_id(plugin_id)
        if not existing:
            from kingsec.application.errors import PluginNotFoundError
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")

        incompat = self._validator.validate_dependencies(manifest, [])
        if incompat:
            from kingsec.application.errors import PluginDependencyError
            raise PluginDependencyError(f"Unmet dependencies: {incompat}")

        install_path = self._installer.install(package_path, manifest)
        plugin = PluginPackage(
            id=manifest.id,
            manifest=manifest,
            status=existing.status if existing.status != PluginInstallStatus.INSTALLING else PluginInstallStatus.INSTALLED,
            installed_version=manifest.version,
            install_path=install_path,
            installed_at=existing.installed_at,
            checksum_verified=bool(manifest.checksum_sha256),
            signature_verified=manifest.signature is not None,
            size_bytes=0,
            health=PluginHealth.HEALTHY,
        )
        self._repo.save(plugin)
        return plugin


class RollbackPlugin:
    def __init__(self, repo: PluginRepositoryPort, installer: PluginInstallerPort) -> None:
        self._repo = repo
        self._installer = installer

    def execute(self, plugin_id: str) -> PluginPackage | None:
        plugin = self._repo.find_by_id(plugin_id)
        if not plugin:
            from kingsec.application.errors import PluginNotFoundError
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")
        self._installer.rollback(plugin_id, plugin.install_path)
        self._repo.update_health(plugin_id, PluginHealth.HEALTHY.value, "")
        self._repo.update_status(plugin_id, PluginInstallStatus.ROLLED_BACK)
        updated = self._repo.find_by_id(plugin_id)
        return updated


class ValidatePlugin:
    def __init__(self, validator: PluginValidatorPort) -> None:
        self._validator = validator

    def execute(self, package_path: str) -> dict:
        from kingsec.application.errors import PluginValidationError
        errors: list[str] = []
        import zipfile
        import json
        try:
            with zipfile.ZipFile(package_path, "r") as zf:
                if "manifest.json" not in zf.namelist():
                    raise PluginValidationError("Missing manifest.json")
                data = json.loads(zf.read("manifest.json"))
                manifest = self._validator.validate_manifest(data)
        except PluginValidationError:
            raise
        except Exception as e:
            raise PluginValidationError(str(e)) from e

        checksum_ok = self._validator.validate_checksum(package_path, manifest.checksum_sha256) if manifest.checksum_sha256 else True
        compat_ok = self._validator.validate_compatibility(manifest)
        sig_ok = True
        if manifest.signature:
            sig_ok = self._validator.validate_signature(package_path, manifest.signature)
        deps = self._validator.validate_dependencies(manifest, [])

        if not checksum_ok:
            errors.append("checksum_mismatch")
        if not compat_ok:
            errors.append("incompatible_version")
        if not sig_ok:
            errors.append("signature_invalid")
        if deps:
            errors.append(f"unmet_dependencies: {deps}")

        return {
            "valid": len(errors) == 0,
            "manifest": {
                "id": manifest.id,
                "name": manifest.name,
                "version": str(manifest.version),
                "author": manifest.author,
                "description": manifest.description,
            },
            "checksum_verified": checksum_ok,
            "compatible": compat_ok,
            "signature_verified": sig_ok,
            "dependencies_met": len(deps) == 0,
            "errors": errors,
        }


class ListPlugins:
    def __init__(self, repo: PluginRepositoryPort) -> None:
        self._repo = repo

    def execute(self) -> list[PluginPackage]:
        return self._repo.find_all()


class GetPlugin:
    def __init__(self, repo: PluginRepositoryPort) -> None:
        self._repo = repo

    def execute(self, plugin_id: str) -> PluginPackage | None:
        return self._repo.find_by_id(plugin_id)


class CheckPluginUpdates:
    def __init__(self, repo: PluginRepositoryPort, marketplace: PluginMarketplacePort) -> None:
        self._repo = repo
        self._marketplace = marketplace

    def execute(self, plugin_id: str) -> list[dict]:
        plugin = self._repo.find_by_id(plugin_id)
        if not plugin:
            from kingsec.application.errors import PluginNotFoundError
            raise PluginNotFoundError(f"Plugin '{plugin_id}' not found")
        return self._marketplace.check_updates(plugin_id, str(plugin.installed_version) if plugin.installed_version else "0.0.0")


class ImportPlugin:
    def __init__(
        self,
        repo: PluginRepositoryPort,
        installer: PluginInstallerPort,
        validator: PluginValidatorPort,
    ) -> None:
        self._repo = repo
        self._installer = installer
        self._validator = validator

    def execute(self, package_path: str, filename: str) -> PluginPackage:
        import zipfile
        import json
        try:
            with zipfile.ZipFile(package_path, "r") as zf:
                if "manifest.json" not in zf.namelist():
                    from kingsec.application.errors import PluginValidationError
                    raise PluginValidationError("Missing manifest.json in plugin archive")
                data = json.loads(zf.read("manifest.json"))
        except (zipfile.BadZipFile, json.JSONDecodeError) as exc:
            from kingsec.application.errors import PluginValidationError
            raise PluginValidationError(f"Invalid plugin archive: {exc}") from exc
        manifest = self._validator.validate_manifest(data)
        use_case = InstallPlugin(self._repo, self._installer, self._validator)
        return use_case.execute(package_path, manifest)


class ExportPlugin:
    def __init__(self, repo: PluginRepositoryPort) -> None:
        self._repo = repo

    def execute(self, plugin_id: str) -> bytes | None:
        plugin = self._repo.find_by_id(plugin_id)
        if not plugin:
            return None
        import zipfile
        import io
        import json
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            manifest_dict = {
                "id": plugin.manifest.id,
                "name": plugin.manifest.name,
                "version": str(plugin.manifest.version),
                "description": plugin.manifest.description,
                "author": plugin.manifest.author,
                "license": plugin.manifest.license,
                "entry_point": plugin.manifest.entry_point,
                "homepage": plugin.manifest.homepage,
                "repository": plugin.manifest.repository,
                "tags": list(plugin.manifest.tags),
                "checksum_sha256": plugin.manifest.checksum_sha256,
            }
            zf.writestr("manifest.json", json.dumps(manifest_dict, indent=2))
        buf.seek(0)
        return buf.getvalue()
