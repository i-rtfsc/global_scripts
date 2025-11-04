"""
Plugin Manager Adapter

Provides a legacy-compatible interface that wraps the new Clean Architecture
components (PluginService, PluginExecutor). This adapter allows gradual migration
by exposing the old PluginManager API while using the new implementation.

This is a temporary migration tool and will be removed once Phase 2 is complete.
"""

import asyncio
from pathlib import Path
from typing import List, Dict, Any, Optional, Union

from ...models import CommandResult
from ...application.services import PluginService, PluginExecutor
from ...plugins.interfaces import PluginEvent, PluginEventData, IPluginObserver
from ...core.logger import get_logger

logger = get_logger(tag="INFRASTRUCTURE.ADAPTER", name=__name__)


class PluginManagerAdapter:
    """
    Adapter that wraps PluginService + PluginExecutor to provide
    legacy PluginManager interface.

    This allows CLI code to use the new architecture without changes.
    """

    def __init__(
        self,
        plugin_service: PluginService,
        plugin_executor: PluginExecutor,
        plugins_root: Union[str, Path] = None,
        config_manager: Any = None,
    ):
        """
        Initialize adapter

        Args:
            plugin_service: New PluginService instance
            plugin_executor: New PluginExecutor instance
            plugins_root: Plugins root directory (for compatibility)
            config_manager: ConfigManager instance (for compatibility)
        """
        self._service = plugin_service
        self._executor = plugin_executor
        self._plugins_root = Path(plugins_root) if plugins_root else None
        self._config_manager = config_manager
        self._initialized = False

        logger.info("PluginManagerAdapter created (migration adapter)")

    async def initialize(self):
        """Initialize plugin system"""
        if self._initialized:
            return

        logger.info("Initializing plugin system via adapter")
        await self._service.load_all_plugins()
        self._initialized = True
        logger.info("Plugin system initialized")

    async def load_all_plugins(self):
        """
        Load all plugins

        Returns:
            Dict: Loaded plugins (for compatibility)
        """
        logger.debug("load_all_plugins called via adapter")
        result = await self._service.load_all_plugins()
        return result

    async def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a specific plugin

        Args:
            plugin_name: Name of plugin to reload

        Returns:
            bool: True if successful
        """
        logger.debug(f"reload_plugin called via adapter: {plugin_name}")
        return await self._service.reload_plugin(plugin_name)

    async def execute_plugin_function(
        self, plugin_name: str, function_name: str, args: List[str] = None
    ) -> CommandResult:
        """
        Execute a plugin function

        Args:
            plugin_name: Name of the plugin
            function_name: Name of the function
            args: Command arguments

        Returns:
            CommandResult: Execution result
        """
        logger.debug(
            f"execute_plugin_function called via adapter: "
            f"plugin={plugin_name}, function={function_name}"
        )
        return await self._executor.execute_plugin_function(
            plugin_name, function_name, args
        )

    async def list_all_plugins(self):
        """
        List all plugins (delegates to wrapped PluginService)

        Returns:
            List: All plugin metadata
        """
        logger.debug("list_all_plugins called via adapter")
        return await self._service.list_all_plugins()

    async def enable_plugin_async(self, plugin_name: str) -> CommandResult:
        """
        Enable a plugin (async version)

        Args:
            plugin_name: Name of plugin to enable

        Returns:
            CommandResult: Result of operation
        """
        logger.debug(f"enable_plugin_async called via adapter: {plugin_name}")
        success = await self._service.enable_plugin(plugin_name)

        if success:
            # Clear repository cache to force reload from filesystem
            logger.info("Clearing repository cache before reloading")
            self._service._repository.clear_cache()
            self._service._loader.clear()

            # Reload all plugins to reflect the change
            logger.info(f"Reloading plugins after enabling {plugin_name}")
            loaded = await self._service.load_all_plugins()
            logger.info(
                f"Loaded {len(loaded)} plugins after enable: {list(loaded.keys())}"
            )

            # Regenerate router index and completions (like legacy system)
            self._generate_router_index()
            self._regenerate_completions()

            return CommandResult(
                success=True, output=f"Plugin '{plugin_name}' enabled", exit_code=0
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to enable plugin '{plugin_name}'",
                exit_code=1,
            )

    def enable_plugin(self, plugin_name: str) -> CommandResult:
        """
        Enable a plugin (sync wrapper for async method)

        Args:
            plugin_name: Name of plugin to enable

        Returns:
            CommandResult: Result of operation
        """
        logger.debug(f"enable_plugin called via adapter: {plugin_name}")

        # Check if we're in an async context
        try:
            loop = asyncio.get_running_loop()
            # We're in an event loop - can't use asyncio.run()
            # Create a task and wait for it
            import nest_asyncio

            nest_asyncio.apply()
            return asyncio.run(self.enable_plugin_async(plugin_name))
        except RuntimeError:
            # No event loop running - safe to use asyncio.run()
            return asyncio.run(self.enable_plugin_async(plugin_name))

    async def disable_plugin_async(self, plugin_name: str) -> CommandResult:
        """
        Disable a plugin (async version)

        Args:
            plugin_name: Name of plugin to disable

        Returns:
            CommandResult: Result of operation
        """
        logger.debug(f"disable_plugin_async called via adapter: {plugin_name}")
        success = await self._service.disable_plugin(plugin_name)

        if success:
            # Clear repository cache to force reload from filesystem
            logger.info("Clearing repository cache before reloading")
            self._service._repository.clear_cache()
            self._service._loader.clear()

            # Reload all plugins to reflect the change
            logger.info(f"Reloading plugins after disabling {plugin_name}")
            await self._service.load_all_plugins()

            # Regenerate router index and completions (like legacy system)
            self._generate_router_index()
            self._regenerate_completions()

            return CommandResult(
                success=True, output=f"Plugin '{plugin_name}' disabled", exit_code=0
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to disable plugin '{plugin_name}'",
                exit_code=1,
            )

    def disable_plugin(self, plugin_name: str) -> CommandResult:
        """
        Disable a plugin (sync wrapper for async method)

        Args:
            plugin_name: Name of plugin to disable

        Returns:
            CommandResult: Result of operation
        """
        logger.debug(f"disable_plugin called via adapter: {plugin_name}")

        # Check if we're in an async context
        try:
            loop = asyncio.get_running_loop()
            # We're in an event loop - can't use asyncio.run()
            import nest_asyncio

            nest_asyncio.apply()
            return asyncio.run(self.disable_plugin_async(plugin_name))
        except RuntimeError:
            # No event loop running - safe to use asyncio.run()
            return asyncio.run(self.disable_plugin_async(plugin_name))

    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """
        Check if plugin is enabled

        Args:
            plugin_name: Name of plugin

        Returns:
            bool: True if enabled
        """
        # Run async method synchronously
        try:
            plugin = asyncio.run(self._service.get_plugin_metadata(plugin_name))
        except RuntimeError:
            import nest_asyncio

            nest_asyncio.apply()
            plugin = asyncio.run(self._service.get_plugin_metadata(plugin_name))

        return plugin.enabled if plugin else False

    def list_plugins(self) -> Dict[str, dict]:
        """
        List all plugins in legacy format

        Returns:
            Dict[str, dict]: Plugin dictionary
        """
        logger.debug("list_plugins called via adapter")

        # Get plugins from new system
        try:
            plugins = asyncio.run(self._service.list_all_plugins())
        except RuntimeError:
            import nest_asyncio

            nest_asyncio.apply()
            plugins = asyncio.run(self._service.list_all_plugins())

        # Convert to legacy format
        result = {}
        for plugin in plugins:
            result[plugin.name] = {
                "name": plugin.name,
                "version": plugin.version,
                "author": plugin.author,
                "description": plugin.description,
                "enabled": plugin.enabled,
                "priority": plugin.priority,
                "category": plugin.category,
                "keywords": plugin.keywords,
                "tags": plugin.tags,
            }

        return result

    def get_plugin_info(self, plugin_name: str) -> Optional[dict]:
        """
        Get detailed plugin information

        Args:
            plugin_name: Name of plugin

        Returns:
            Optional[dict]: Plugin info or None
        """
        logger.debug(f"get_plugin_info called via adapter: {plugin_name}")

        try:
            info = asyncio.run(self._service.get_plugin_info(plugin_name))
        except RuntimeError:
            import nest_asyncio

            nest_asyncio.apply()
            info = asyncio.run(self._service.get_plugin_info(plugin_name))

        return info

    def search_functions(self, keyword: str) -> List[dict]:
        """
        Search for functions by keyword

        Args:
            keyword: Search keyword

        Returns:
            List[dict]: Matching functions
        """
        logger.debug(f"search_functions called via adapter: {keyword}")

        try:
            results = asyncio.run(self._service.search_functions(keyword))
        except RuntimeError:
            import nest_asyncio

            nest_asyncio.apply()
            results = asyncio.run(self._service.search_functions(keyword))

        return results

    def get_all_shortcuts(self) -> Dict[str, str]:
        """
        Get all plugin shortcuts

        Returns:
            Dict[str, str]: Shortcut mappings
        """
        logger.debug("get_all_shortcuts called via adapter")
        return self._service.get_all_shortcuts()

    def generate_shell_functions(self, output_file: Path):
        """
        Generate shell functions (compatibility method)

        Args:
            output_file: Output file path
        """
        logger.warning(
            "generate_shell_functions called via adapter - "
            "this should use router/indexer instead"
        )
        # This method is handled by router/indexer in new architecture
        # For now, just log a warning
        pass

    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check

        Returns:
            Dict[str, Any]: Health status
        """
        logger.debug("health_check called via adapter")
        return await self._service.health_check()

    def register_observer(self, observer: IPluginObserver) -> None:
        """
        Register observer for plugin events

        Args:
            observer: Observer instance
        """
        logger.debug(f"register_observer called via adapter: {observer}")
        self._service.register_observer(observer)

    def unregister_observer(self, observer: IPluginObserver) -> None:
        """
        Unregister observer

        Args:
            observer: Observer instance
        """
        logger.debug(f"unregister_observer called via adapter: {observer}")
        self._service.unregister_observer(observer)

    def notify_observers(self, event_data: PluginEventData) -> None:
        """
        Notify observers of event (compatibility method)

        Args:
            event_data: Event data
        """
        # Map to appropriate service notification method
        if event_data.event == PluginEvent.LOADED:
            self._service.notify_observers_loaded(event_data.plugin_name)
        elif event_data.event == PluginEvent.ENABLED:
            self._service.notify_observers_enabled(event_data.plugin_name)
        elif event_data.event == PluginEvent.DISABLED:
            self._service.notify_observers_disabled(event_data.plugin_name)
        elif event_data.event == PluginEvent.ERROR:
            error_msg = event_data.metadata.get("error", "Unknown error")
            self._service.notify_observers_error(event_data.plugin_name, error_msg)

    def _generate_router_index(self):
        """Regenerate router index for shell/json command routing"""
        try:
            from ...router.indexer import build_router_index, write_router_index

            # Build router index from loaded plugins
            router_index = build_router_index(self.plugins)
            write_router_index(router_index)
            logger.info("Router index regenerated successfully")
        except Exception as e:
            logger.error(f"Failed to regenerate router index: {e}")

    def _regenerate_completions(self):
        """Regenerate shell completions (placeholder - legacy behavior)"""
        try:
            # Note: Completion regeneration typically requires external script
            # For now, just log that it should be regenerated
            logger.info(
                "Completions should be regenerated - run: uv run python scripts/setup.py"
            )
        except Exception as e:
            logger.error(f"Failed to regenerate completions: {e}")

    # Properties for compatibility
    @property
    def plugin_loader(self):
        """Get plugin loader (compatibility)"""
        return self._service._loader

    @property
    def plugins(self):
        """Get loaded plugins (compatibility)"""
        return self._service.get_loaded_plugins()

    @property
    def failed_plugins(self):
        """Get failed plugins (compatibility)"""
        return self._service.get_failed_plugins()


__all__ = ["PluginManagerAdapter"]
