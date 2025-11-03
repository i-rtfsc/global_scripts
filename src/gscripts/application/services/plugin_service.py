"""
Plugin Service
Application layer service for plugin management
"""

from typing import List, Optional, Dict, Any, Protocol
from pathlib import Path

from ...domain.interfaces import IPluginLoader, IPluginRepository
from ...models.plugin import PluginMetadata, PluginType
from ...models import CommandResult


# Observer interface (will move to domain/interfaces later)
class IPluginObserver(Protocol):
    """Observer interface for plugin lifecycle events"""

    def on_plugin_loaded(self, plugin_name: str) -> None:
        """Called when plugin is loaded"""
        ...

    def on_plugin_enabled(self, plugin_name: str) -> None:
        """Called when plugin is enabled"""
        ...

    def on_plugin_disabled(self, plugin_name: str) -> None:
        """Called when plugin is disabled"""
        ...

    def on_plugin_error(self, plugin_name: str, error: str) -> None:
        """Called when plugin encounters error"""
        ...


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
        self._observers: List[IPluginObserver] = []

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

        # Notify observers
        self.notify_observers_enabled(plugin_name)

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

        # Notify observers
        self.notify_observers_disabled(plugin_name)

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

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on plugin system

        Returns:
            Dict[str, Any]: Health status including plugin counts and errors
        """
        all_plugins = await self.list_all_plugins()
        enabled = await self.get_enabled_plugins()
        disabled = await self.get_disabled_plugins()
        loaded = self.get_loaded_plugins()
        failed = self.get_failed_plugins()

        return {
            "status": "healthy" if not failed else "degraded",
            "total_plugins": len(all_plugins),
            "enabled_count": len(enabled),
            "disabled_count": len(disabled),
            "loaded_count": len(loaded),
            "failed_count": len(failed),
            "failed_plugins": list(failed.keys()) if failed else [],
        }

    async def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginMetadata]:
        """
        Get plugins of specific type

        Args:
            plugin_type: Type of plugins to filter

        Returns:
            List[PluginMetadata]: Plugins of specified type
        """
        all_plugins = await self.list_all_plugins()
        return [p for p in all_plugins if p.type == plugin_type]

    async def search_functions(self, keyword: str) -> List[Dict[str, Any]]:
        """
        Search for functions by keyword

        Args:
            keyword: Keyword to search for

        Returns:
            List[Dict[str, Any]]: Matching functions
        """
        results = []
        loaded = self.get_loaded_plugins()

        keyword_lower = keyword.lower()

        for plugin_name, plugin_info in loaded.items():
            functions = plugin_info.get('functions', {})
            for func_name, func_info in functions.items():
                # Search in function name and description
                if keyword_lower in func_name.lower():
                    results.append({
                        'plugin': plugin_name,
                        'function': func_name,
                        'description': func_info.get('description', ''),
                        'usage': func_info.get('usage', ''),
                    })
                elif 'description' in func_info:
                    desc = func_info['description']
                    desc_str = desc if isinstance(desc, str) else str(desc)
                    if keyword_lower in desc_str.lower():
                        results.append({
                            'plugin': plugin_name,
                            'function': func_name,
                            'description': func_info.get('description', ''),
                            'usage': func_info.get('usage', ''),
                        })

        return results

    async def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a plugin

        Args:
            plugin_name: Name of plugin to reload

        Returns:
            bool: True if successful
        """
        # Reload plugin from loader
        plugin = await self._loader.load_plugin(plugin_name)
        return plugin is not None

    def get_all_shortcuts(self) -> Dict[str, str]:
        """
        Get all plugin shortcuts

        Returns:
            Dict[str, str]: Mapping of shortcuts to commands
        """
        # Shortcuts would come from plugin metadata or loader
        # For now, return empty dict (implementation depends on loader)
        shortcuts = {}
        loaded = self.get_loaded_plugins()

        for plugin_name, plugin_info in loaded.items():
            # Get shortcuts from plugin info if available
            plugin_shortcuts = plugin_info.get('shortcuts', {})
            shortcuts.update(plugin_shortcuts)

        return shortcuts

    # Observer pattern methods
    def register_observer(self, observer: IPluginObserver) -> None:
        """
        Register an observer for plugin lifecycle events

        Args:
            observer: Observer to register
        """
        if observer not in self._observers:
            self._observers.append(observer)

    def unregister_observer(self, observer: IPluginObserver) -> None:
        """
        Unregister an observer

        Args:
            observer: Observer to unregister
        """
        if observer in self._observers:
            self._observers.remove(observer)

    def notify_observers_loaded(self, plugin_name: str) -> None:
        """Notify observers that plugin was loaded"""
        for observer in self._observers:
            try:
                observer.on_plugin_loaded(plugin_name)
            except Exception:
                pass  # Don't let observer errors break the service

    def notify_observers_enabled(self, plugin_name: str) -> None:
        """Notify observers that plugin was enabled"""
        for observer in self._observers:
            try:
                observer.on_plugin_enabled(plugin_name)
            except Exception:
                pass

    def notify_observers_disabled(self, plugin_name: str) -> None:
        """Notify observers that plugin was disabled"""
        for observer in self._observers:
            try:
                observer.on_plugin_disabled(plugin_name)
            except Exception:
                pass

    def notify_observers_error(self, plugin_name: str, error: str) -> None:
        """Notify observers of plugin error"""
        for observer in self._observers:
            try:
                observer.on_plugin_error(plugin_name, error)
            except Exception:
                pass


__all__ = ['PluginService', 'IPluginObserver']
