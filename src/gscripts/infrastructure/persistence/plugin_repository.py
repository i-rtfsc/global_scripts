"""
Plugin Repository Implementation
Manages plugin persistence and retrieval
"""

from pathlib import Path
from typing import List, Optional, Dict, Any

from ...domain.interfaces import IPluginRepository, IFileSystem
from ...models.plugin import PluginMetadata, PluginType


class PluginRepository(IPluginRepository):
    """Plugin repository implementation using filesystem with router.json cache support"""

    def __init__(
        self,
        filesystem: IFileSystem,
        plugins_dir: Path,
        router_cache_path: Optional[Path] = None,
    ):
        """
        Initialize plugin repository

        Args:
            filesystem: Filesystem abstraction
            plugins_dir: Base directory containing plugins
            router_cache_path: Path to router.json cache file (optional)
        """
        self._fs = filesystem
        self._plugins_dir = plugins_dir
        self._router_cache_path = router_cache_path
        self._cache: Dict[str, PluginMetadata] = {}

    async def get_all(self) -> List[PluginMetadata]:
        """
        Get all plugins

        Strategy:
        1. Try to load from router.json cache first
        2. If cache doesn't exist or fails, scan plugin directories
        """
        # Try router.json cache first
        if self._router_cache_path and self._fs.exists(self._router_cache_path):
            try:
                cache_data = self._fs.read_json(self._router_cache_path)
                plugins_data = cache_data.get("plugins", {})

                plugins = []
                for plugin_name, plugin_data in plugins_data.items():
                    try:
                        plugin = self._parse_plugin_metadata(plugin_data, plugin_name)
                        plugins.append(plugin)
                        self._cache[plugin.name] = plugin
                    except Exception:
                        # Skip invalid plugin entries
                        continue

                if plugins:  # If we got plugins from cache, return them
                    return plugins
            except Exception:
                # Cache read failed, fall through to directory scan
                pass

        # Fallback: Scan plugin directories
        plugins = []
        if not self._fs.exists(self._plugins_dir):
            return plugins

        for plugin_dir in self._fs.list_dir(self._plugins_dir):
            plugin_json = plugin_dir / "plugin.json"
            if self._fs.exists(plugin_json):
                try:
                    data = self._fs.read_json(plugin_json)
                    plugin = self._parse_plugin_metadata(data, plugin_dir.name)
                    plugins.append(plugin)
                    self._cache[plugin.name] = plugin
                except Exception:
                    # Skip invalid plugins
                    continue

        return plugins

    async def get_by_name(self, name: str) -> Optional[PluginMetadata]:
        """
        Get plugin by name

        Strategy:
        1. Check in-memory cache first
        2. Try router.json cache
        3. Fallback to filesystem scan
        """
        # Check in-memory cache first
        if name in self._cache:
            return self._cache[name]

        # Try router.json cache
        if self._router_cache_path and self._fs.exists(self._router_cache_path):
            try:
                cache_data = self._fs.read_json(self._router_cache_path)
                plugins_data = cache_data.get("plugins", {})

                if name in plugins_data:
                    plugin = self._parse_plugin_metadata(plugins_data[name], name)
                    self._cache[name] = plugin
                    return plugin
            except Exception:
                # Cache read failed, fall through to filesystem
                pass

        # Fallback: Try to load from filesystem
        plugin_dir = self._plugins_dir / name
        plugin_json = plugin_dir / "plugin.json"

        if not self._fs.exists(plugin_json):
            return None

        try:
            data = self._fs.read_json(plugin_json)
            plugin = self._parse_plugin_metadata(data, name)
            self._cache[name] = plugin
            return plugin
        except Exception:
            return None

    async def save(self, plugin: PluginMetadata) -> None:
        """Save plugin metadata"""
        plugin_dir = self._plugins_dir / plugin.name
        plugin_json = plugin_dir / "plugin.json"

        # Read existing data
        if self._fs.exists(plugin_json):
            data = self._fs.read_json(plugin_json)
        else:
            data = {}

        # Update with new metadata
        data.update(
            {
                "name": plugin.name,
                "version": plugin.version,
                "author": plugin.author,
                "description": plugin.description,
                "homepage": plugin.homepage,
                "license": plugin.license,
                "enabled": plugin.enabled,
                "priority": plugin.priority,
                "category": plugin.category,
                "keywords": plugin.keywords,
                "requirements": plugin.requirements,
                "tags": plugin.tags,
                "subplugins": plugin.subplugins,
            }
        )

        # Write back to filesystem
        self._fs.write_json(plugin_json, data)

        # Update cache
        self._cache[plugin.name] = plugin

    async def delete(self, name: str) -> bool:
        """Delete plugin (mark as disabled)"""
        plugin = await self.get_by_name(name)
        if not plugin:
            return False

        plugin.enabled = False
        await self.save(plugin)
        return True

    async def get_enabled(self) -> List[PluginMetadata]:
        """
        Get all enabled plugins

        Returns:
            List[PluginMetadata]: List of enabled plugins
        """
        all_plugins = await self.get_all()
        return [p for p in all_plugins if p.enabled]

    async def get_by_type(self, plugin_type: PluginType) -> List[PluginMetadata]:
        """
        Get plugins by type

        Args:
            plugin_type: Type of plugins to filter (python, shell, config, hybrid)

        Returns:
            List[PluginMetadata]: List of plugins of the specified type
        """
        all_plugins = await self.get_all()
        return [p for p in all_plugins if p.type == plugin_type]

    async def update_enabled_status(self, name: str, enabled: bool) -> bool:
        """
        Update the enabled status of a plugin

        Args:
            name: Plugin name
            enabled: New enabled status

        Returns:
            bool: True if successful, False if plugin not found
        """
        plugin = await self.get_by_name(name)
        if not plugin:
            return False

        plugin.enabled = enabled
        await self.save(plugin)
        return True

    def _parse_plugin_metadata(self, data: Dict[str, Any], name: str) -> PluginMetadata:
        """Parse plugin metadata from JSON data"""
        # Parse type string to PluginType enum
        type_str = data.get("type", "unknown").lower()

        # Map alternate names to canonical types
        type_mapping = {
            "json": "config",
            "script": "shell",
            "sh": "shell",
        }
        type_str = type_mapping.get(type_str, type_str)

        try:
            plugin_type = PluginType(type_str)
        except ValueError:
            plugin_type = PluginType.UNKNOWN

        return PluginMetadata(
            name=data.get("name", name),
            version=data.get("version", "1.0.0"),
            author=data.get("author", "Unknown"),
            description=data.get("description", ""),
            homepage=data.get("homepage", ""),
            license=data.get("license", ""),
            enabled=data.get("enabled", True),
            priority=data.get("priority", 50),
            category=data.get("category", ""),
            keywords=data.get("keywords", []),
            requirements=data.get("requirements", {}),
            tags=data.get("tags", []),
            subplugins=data.get("subplugins", []),
            type=plugin_type,
        )

    def clear_cache(self) -> None:
        """Clear the internal cache (useful for testing)"""
        self._cache.clear()


__all__ = ["PluginRepository"]
