"""
Plugin Service
Application layer service for plugin management
"""

from typing import List, Optional, Dict, Any
from pathlib import Path

from ...domain.interfaces import IPluginLoader, IPluginRepository
from ...models.plugin import PluginMetadata


class PluginService:
    """
    Plugin management service

    Provides high-level plugin operations:
    - Loading and unloading plugins
    - Enabling/disabling plugins
    - Querying plugin information
    """

    def __init__(
        self,
        plugin_loader: IPluginLoader,
        plugin_repository: IPluginRepository
    ):
        """
        Initialize plugin service

        Args:
            plugin_loader: Plugin loader instance
            plugin_repository: Plugin repository instance
        """
        self._loader = plugin_loader
        self._repository = plugin_repository

    async def load_all_plugins(self, include_examples: bool = False) -> Dict[str, Any]:
        """
        Load all enabled plugins

        Args:
            include_examples: Whether to include example plugins

        Returns:
            Dict[str, Any]: Loaded plugins
        """
        return await self._loader.load_all_plugins(include_examples)

    async def load_plugin(self, plugin_name: str) -> Optional[Any]:
        """
        Load single plugin by name

        Args:
            plugin_name: Name of the plugin

        Returns:
            Optional[Any]: Plugin info or None
        """
        return await self._loader.load_plugin(plugin_name)

    async def get_plugin_metadata(self, plugin_name: str) -> Optional[PluginMetadata]:
        """
        Get plugin metadata

        Args:
            plugin_name: Name of the plugin

        Returns:
            Optional[PluginMetadata]: Plugin metadata or None
        """
        return await self._repository.get_by_name(plugin_name)

    async def list_all_plugins(self) -> List[PluginMetadata]:
        """
        List all plugins (enabled and disabled)

        Returns:
            List[PluginMetadata]: All plugins
        """
        return await self._repository.get_all()

    async def enable_plugin(self, plugin_name: str) -> bool:
        """
        Enable a plugin

        Args:
            plugin_name: Name of the plugin

        Returns:
            bool: True if successful
        """
        plugin = await self._repository.get_by_name(plugin_name)
        if not plugin:
            return False

        plugin.enabled = True
        await self._repository.save(plugin)
        return True

    async def disable_plugin(self, plugin_name: str) -> bool:
        """
        Disable a plugin

        Args:
            plugin_name: Name of the plugin

        Returns:
            bool: True if successful
        """
        plugin = await self._repository.get_by_name(plugin_name)
        if not plugin:
            return False

        plugin.enabled = False
        await self._repository.save(plugin)
        return True

    async def get_plugin_info(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed plugin information

        Args:
            plugin_name: Name of the plugin

        Returns:
            Optional[Dict[str, Any]]: Plugin information
        """
        # Get metadata
        metadata = await self.get_plugin_metadata(plugin_name)
        if not metadata:
            return None

        # Get loaded plugin info
        loaded_plugins = self._loader.get_loaded_plugins()
        plugin_info = loaded_plugins.get(plugin_name)

        return {
            'name': metadata.name,
            'version': metadata.version,
            'author': metadata.author,
            'description': metadata.description,
            'enabled': metadata.enabled,
            'priority': metadata.priority,
            'category': metadata.category,
            'keywords': metadata.keywords,
            'tags': metadata.tags,
            'loaded': plugin_info is not None,
            'functions': plugin_info.get('functions', []) if plugin_info else [],
        }

    async def get_enabled_plugins(self) -> List[PluginMetadata]:
        """
        Get all enabled plugins

        Returns:
            List[PluginMetadata]: Enabled plugins
        """
        all_plugins = await self.list_all_plugins()
        return [p for p in all_plugins if p.enabled]

    async def get_disabled_plugins(self) -> List[PluginMetadata]:
        """
        Get all disabled plugins

        Returns:
            List[PluginMetadata]: Disabled plugins
        """
        all_plugins = await self.list_all_plugins()
        return [p for p in all_plugins if not p.enabled]

    def get_loaded_plugins(self) -> Dict[str, Any]:
        """Get currently loaded plugins"""
        return self._loader.get_loaded_plugins()

    def get_failed_plugins(self) -> Dict[str, str]:
        """Get plugins that failed to load"""
        return self._loader.get_failed_plugins()


__all__ = ['PluginService']
