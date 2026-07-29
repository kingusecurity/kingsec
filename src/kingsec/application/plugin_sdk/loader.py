from __future__ import annotations

import importlib.util
import logging
import sys
from pathlib import Path
from typing import Any

from kingsec.domain.plugin_extensions import PluginRuntime, PluginSdkManifest, PluginType

from .base import BasePlugin

logger = logging.getLogger(__name__)

PLUGIN_TYPE_MAP: dict[PluginType, type[BasePlugin]] = {}


def register_plugin_type(ptype: PluginType, base_cls: type[BasePlugin]) -> None:
    PLUGIN_TYPE_MAP[ptype] = base_cls


class PluginLoader:
    def __init__(self, plugins_dir: str | Path) -> None:
        self._plugins_dir = Path(plugins_dir)
        self._loaded: dict[str, BasePlugin] = {}

    def discover(self) -> list[PluginSdkManifest]:
        manifests: list[PluginSdkManifest] = []
        if not self._plugins_dir.exists():
            return manifests
        for entry in self._plugins_dir.iterdir():
            if entry.is_dir():
                manifest_path = entry / "plugin.json"
                if manifest_path.exists():
                    try:
                        import json
                        data = json.loads(manifest_path.read_text())
                        manifest = PluginSdkManifest.from_dict(data)
                        manifests.append(manifest)
                    except Exception as exc:
                        logger.warning("Failed to load manifest from %s: %s", manifest_path, exc)
        return manifests

    def load(self, manifest: PluginSdkManifest) -> BasePlugin | None:
        if manifest.id in self._loaded:
            return self._loaded[manifest.id]
        plugin_dir = self._plugins_dir / manifest.id
        if not plugin_dir.exists():
            logger.error("Plugin directory not found: %s", plugin_dir)
            return None
        entry_path = plugin_dir / manifest.entrypoint
        if not entry_path.exists():
            logger.error("Entry point not found: %s", entry_path)
            return None
        try:
            spec = importlib.util.spec_from_file_location(f"kingsec_plugin_{manifest.id}", entry_path)
            if not spec or not spec.loader:
                return None
            module = importlib.util.module_from_spec(spec)
            sys.modules[f"kingsec_plugin_{manifest.id}"] = module
            spec.loader.exec_module(module)
            base_cls = PLUGIN_TYPE_MAP.get(manifest.category)
            for attr_name in dir(module):
                obj = getattr(module, attr_name)
                if isinstance(obj, type) and issubclass(obj, base_cls) if base_cls else False:
                    instance: BasePlugin = obj()
                    instance.id = manifest.id
                    instance.name = manifest.name
                    instance.version = manifest.version
                    instance.author = manifest.author
                    self._loaded[manifest.id] = instance
                    logger.info("Loaded plugin: %s v%s", manifest.name, manifest.version)
                    return instance
            logger.warning("No valid plugin class found in %s", entry_path)
            return None
        except Exception as exc:
            logger.exception("Failed to load plugin %s: %s", manifest.id, exc)
            return None

    def get_loaded(self, plugin_id: str) -> BasePlugin | None:
        return self._loaded.get(plugin_id)

    def all_loaded(self) -> dict[str, BasePlugin]:
        return dict(self._loaded)

    def unload(self, plugin_id: str) -> None:
        instance = self._loaded.pop(plugin_id, None)
        if instance:
            try:
                instance.shutdown()
            except Exception as exc:
                logger.warning("Plugin %s shutdown error: %s", plugin_id, exc)

    def unload_all(self) -> None:
        for pid in list(self._loaded):
            self.unload(pid)
