from __future__ import annotations

from typing import Any

from kingsec.application.ports.outbound import PluginRepositoryPort
from kingsec.domain.plugin_package import PluginHealth, PluginInstallStatus, PluginPackage


class InMemoryPluginRepository(PluginRepositoryPort):
    """In-memory test double — no SQLAlchemy dependency."""

    def __init__(self) -> None:
        self._plugins: dict[str, PluginPackage] = {}

    def save(self, plugin: PluginPackage) -> None:
        self._plugins[plugin.id] = plugin

    def find_by_id(self, plugin_id: str) -> PluginPackage | None:
        return self._plugins.get(plugin_id)

    def find_all(self) -> list[PluginPackage]:
        return list(self._plugins.values())

    def delete(self, plugin_id: str) -> None:
        self._plugins.pop(plugin_id, None)

    def update_status(self, plugin_id: str, status: PluginInstallStatus) -> None:
        plugin = self._plugins.get(plugin_id)
        if plugin:
            self._plugins[plugin_id] = PluginPackage(
                id=plugin.id,
                manifest=plugin.manifest,
                status=status,
                installed_version=plugin.installed_version,
                install_path=plugin.install_path,
                installed_at=plugin.installed_at,
                updated_at=plugin.updated_at,
                health=plugin.health,
                error_message=plugin.error_message,
                size_bytes=plugin.size_bytes,
                checksum_verified=plugin.checksum_verified,
                signature_verified=plugin.signature_verified,
            )

    def update_health(self, plugin_id: str, health: str, error_message: str) -> None:
        plugin = self._plugins.get(plugin_id)
        if plugin:
            self._plugins[plugin_id] = PluginPackage(
                id=plugin.id,
                manifest=plugin.manifest,
                status=plugin.status,
                installed_version=plugin.installed_version,
                install_path=plugin.install_path,
                installed_at=plugin.installed_at,
                updated_at=plugin.updated_at,
                health=PluginHealth(health),
                error_message=error_message,
                size_bytes=plugin.size_bytes,
                checksum_verified=plugin.checksum_verified,
                signature_verified=plugin.signature_verified,
            )


class SQLAlchemyPluginRepository(PluginRepositoryPort):
    """Production SQL persistence for plugins."""

    def __init__(self, session_factory: Any) -> None:
        self._session_factory = session_factory

    def save(self, plugin: PluginPackage) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(
                text("""
                    INSERT OR REPLACE INTO plugins
                        (id, name, version, description, author, license, status,
                         install_path, health, error_message, checksum_verified,
                         signature_verified, installed_at)
                    VALUES
                        (:id, :name, :version, :description, :author, :license, :status,
                         :install_path, :health, :error_message, :checksum_verified,
                         :signature_verified, :installed_at)
                """),
                {
                    "id": plugin.id,
                    "name": plugin.manifest.name,
                    "version": str(plugin.manifest.version) if plugin.manifest.version else "",
                    "description": plugin.manifest.description,
                    "author": plugin.manifest.author,
                    "license": plugin.manifest.license,
                    "status": plugin.status.value,
                    "install_path": plugin.install_path,
                    "health": plugin.health.value,
                    "error_message": plugin.error_message,
                    "checksum_verified": int(plugin.checksum_verified),
                    "signature_verified": int(plugin.signature_verified),
                    "installed_at": plugin.installed_at,
                },
            )
            session.commit()

    def find_by_id(self, plugin_id: str) -> PluginPackage | None:
        from sqlalchemy import text

        with self._session_factory() as session:
            row = session.execute(
                text("SELECT * FROM plugins WHERE id = :id"),
                {"id": plugin_id},
            ).fetchone()
            if not row:
                return None
            return self._row_to_package(row._mapping)

    def find_all(self) -> list[PluginPackage]:
        from sqlalchemy import text

        with self._session_factory() as session:
            rows = session.execute(text("SELECT * FROM plugins")).fetchall()
            return [self._row_to_package(r._mapping) for r in rows]

    def delete(self, plugin_id: str) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(text("DELETE FROM plugins WHERE id = :id"), {"id": plugin_id})
            session.commit()

    def update_status(self, plugin_id: str, status: PluginInstallStatus) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(
                text("UPDATE plugins SET status = :status WHERE id = :id"),
                {"id": plugin_id, "status": status.value},
            )
            session.commit()

    def update_health(self, plugin_id: str, health: str, error_message: str) -> None:
        from sqlalchemy import text

        with self._session_factory() as session:
            session.execute(
                text("UPDATE plugins SET health = :health, error_message = :error_message WHERE id = :id"),
                {"id": plugin_id, "health": health, "error_message": error_message},
            )
            session.commit()

    def _row_to_package(self, row: Any) -> PluginPackage:
        from kingsec.domain.plugin_package import (
            PluginHealth,
            PluginInstallStatus,
            PluginManifest,
            PluginVersion,
        )

        manifest = PluginManifest(
            id=row["id"],
            name=row.get("name", ""),
            version=PluginVersion.parse(row.get("version", "0.0.0")),
            description=row.get("description", ""),
            author=row.get("author", ""),
            license=row.get("license", ""),
            entry_point=row.get("entry_point", ""),
        )
        return PluginPackage(
            id=row["id"],
            manifest=manifest,
            status=PluginInstallStatus(row.get("status", PluginInstallStatus.NOT_INSTALLED.value)),
            installed_version=PluginVersion.parse(row.get("version", "0.0.0")),
            install_path=row.get("install_path", ""),
            installed_at=row.get("installed_at", ""),
            health=PluginHealth(row.get("health", PluginHealth.UNKNOWN.value)),
            error_message=row.get("error_message", ""),
            checksum_verified=bool(row.get("checksum_verified", 0)),
            signature_verified=bool(row.get("signature_verified", 0)),
        )
