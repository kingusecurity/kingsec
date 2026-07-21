from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound import (
    PluginInstallerPort,
    PluginMarketplacePort,
    PluginRepositoryPort,
    PluginValidatorPort,
)
from kingsec.application.ports.plugin_service import PluginServicePort
from kingsec.application.use_cases.plugins import (
    CheckPluginUpdates,
    DisablePlugin,
    EnablePlugin,
    ExportPlugin,
    GetPlugin,
    ImportPlugin,
    InstallPlugin,
    ListPlugins,
    RollbackPlugin,
    UninstallPlugin,
    UpdatePlugin,
    ValidatePlugin,
)
from kingsec.domain.plugin_package import PluginPackage


class PluginService(PluginServicePort):
    def __init__(
        self,
        repo: PluginRepositoryPort,
        installer: PluginInstallerPort,
        validator: PluginValidatorPort,
        marketplace: PluginMarketplacePort | None = None,
    ) -> None:
        self._install_uc = InstallPlugin(repo, installer, validator)
        self._uninstall_uc = UninstallPlugin(repo, installer)
        self._enable_uc = EnablePlugin(repo)
        self._disable_uc = DisablePlugin(repo)
        self._update_uc = UpdatePlugin(repo, installer, validator)
        self._rollback_uc = RollbackPlugin(repo, installer)
        self._validate_uc = ValidatePlugin(validator)
        self._list_uc = ListPlugins(repo)
        self._get_uc = GetPlugin(repo)
        self._check_updates_uc = CheckPluginUpdates(repo, marketplace) if marketplace else None
        self._import_uc = ImportPlugin(repo, installer, validator)
        self._export_uc = ExportPlugin(repo)

    def _extract_manifest(self, package_path: str, filename: str | None = None) -> Any:
        import json
        import zipfile

        with zipfile.ZipFile(package_path, "r") as zf:
            if "manifest.json" not in zf.namelist():
                from kingsec.application.errors import PluginValidationError

                raise PluginValidationError("Missing manifest.json in plugin archive")
            data = json.loads(zf.read("manifest.json"))
        from kingsec.domain.plugin_package import PluginManifest, PluginVersion

        return PluginManifest(
            id=data["id"],
            name=data["name"],
            version=PluginVersion.parse(data["version"]),
            description=data.get("description", ""),
            author=data.get("author", ""),
            license=data.get("license", ""),
            entry_point=data.get("entry_point", ""),
            homepage=data.get("homepage", ""),
            repository=data.get("repository", ""),
            tags=tuple(data.get("tags", [])),
            checksum_sha256=data.get("checksum_sha256", ""),
        )

    def install(self, package_path: str, filename: str) -> PluginPackage:
        import json
        import zipfile

        from kingsec.domain.plugin_package import PluginManifest, PluginVersion

        with zipfile.ZipFile(package_path, "r") as zf:
            if "manifest.json" not in zf.namelist():
                from kingsec.application.errors import PluginValidationError

                raise PluginValidationError("Missing manifest.json in plugin archive")
            data = json.loads(zf.read("manifest.json"))
        manifest = PluginManifest(
            id=data["id"],
            name=data["name"],
            version=PluginVersion.parse(data["version"]),
            description=data.get("description", ""),
            author=data.get("author", ""),
            license=data.get("license", ""),
            entry_point=data.get("entry_point", ""),
            homepage=data.get("homepage", ""),
            repository=data.get("repository", ""),
            tags=tuple(data.get("tags", [])),
            checksum_sha256=data.get("checksum_sha256", ""),
        )
        return self._install_uc.execute(package_path, manifest)

    def uninstall(self, plugin_id: str) -> None:
        self._uninstall_uc.execute(plugin_id)

    def enable(self, plugin_id: str) -> PluginPackage:
        return self._enable_uc.execute(plugin_id)

    def disable(self, plugin_id: str) -> PluginPackage:
        return self._disable_uc.execute(plugin_id)

    def update(self, plugin_id: str, package_path: str, filename: str) -> PluginPackage:
        import json
        import zipfile

        from kingsec.domain.plugin_package import PluginManifest, PluginVersion

        with zipfile.ZipFile(package_path, "r") as zf:
            if "manifest.json" not in zf.namelist():
                from kingsec.application.errors import PluginValidationError

                raise PluginValidationError("Missing manifest.json in plugin archive")
            data = json.loads(zf.read("manifest.json"))
        manifest = PluginManifest(
            id=data["id"],
            name=data["name"],
            version=PluginVersion.parse(data["version"]),
            description=data.get("description", ""),
            author=data.get("author", ""),
            license=data.get("license", ""),
            entry_point=data.get("entry_point", ""),
            homepage=data.get("homepage", ""),
            repository=data.get("repository", ""),
            tags=tuple(data.get("tags", [])),
            checksum_sha256=data.get("checksum_sha256", ""),
        )
        return self._update_uc.execute(plugin_id, package_path, manifest)

    def rollback(self, plugin_id: str) -> PluginPackage | None:
        return self._rollback_uc.execute(plugin_id)

    def validate(self, package_path: str) -> dict[str, Any]:
        return self._validate_uc.execute(package_path)

    def list_plugins(self) -> list[PluginPackage]:
        return self._list_uc.execute()

    def get_plugin(self, plugin_id: str) -> PluginPackage | None:
        return self._get_uc.execute(plugin_id)

    def check_updates(self, plugin_id: str) -> list[dict[str, Any]]:
        if not self._check_updates_uc:
            return []
        return self._check_updates_uc.execute(plugin_id)

    def import_plugin(self, package_path: str, filename: str) -> PluginPackage:
        return self._import_uc.execute(package_path, filename)

    def export_plugin(self, plugin_id: str) -> bytes | None:
        return self._export_uc.execute(plugin_id)
