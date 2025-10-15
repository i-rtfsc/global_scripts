"""
New PluginLoader Implementation
Implements IPluginLoader using repository pattern
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any

from ...domain.interfaces import IPluginLoader, IPluginRepository
from ...models.plugin import PluginMetadata
from ...plugins.discovery import PluginDiscovery
from ...plugins.validators import PluginValidator
from ...plugins.parsers import FunctionParserRegistry
from ...plugins.parsers.python_parser import PythonFunctionParser
from ...plugins.parsers.shell_parser import ShellFunctionParser
from ...plugins.parsers.config_parser import ConfigFunctionParser


class PluginLoader(IPluginLoader):
    """
    New plugin loader implementation

    Uses repository pattern for data access
    Separates plugin metadata from plugin loading logic
    """

    def __init__(
        self,
        plugin_repository: IPluginRepository,
        plugins_root: Path
    ):
        """
        Initialize plugin loader

        Args:
            plugin_repository: Plugin repository for data access
            plugins_root: Root directory containing plugins
        """
        self._repository = plugin_repository
        self._plugins_root = plugins_root

        # Components
        self._discovery = PluginDiscovery(plugins_root)
        self._validator = PluginValidator()
        self._parser_registry = FunctionParserRegistry()

        # Register parsers
        self._register_parsers()

        # Storage
        self._loaded_plugins: Dict[str, Any] = {}
        self._failed_plugins: Dict[str, str] = {}

    def _register_parsers(self) -> None:
        """Register all function parsers"""
        self._parser_registry.register(PythonFunctionParser())
        self._parser_registry.register(ShellFunctionParser())
        self._parser_registry.register(ConfigFunctionParser())

    async def load_all_plugins(self, include_examples: bool = False) -> Dict[str, Any]:
        """
        Load all plugins

        Args:
            include_examples: Whether to include example plugins

        Returns:
            Dict[str, Any]: Loaded plugins dictionary
        """
        # 1. Get plugin metadata from repository
        plugins_meta = await self._repository.get_all()

        # 2. Filter enabled plugins
        enabled_plugins = [p for p in plugins_meta if p.enabled]

        # 3. Discover plugin directories
        plugin_dirs = self._discovery.discover_all_plugins(include_examples)

        # 4. Load plugins in parallel
        tasks = []
        for plugin_dir in plugin_dirs:
            plugin_name = plugin_dir.name

            # Find matching metadata
            meta = next((p for p in enabled_plugins if p.name == plugin_name), None)

            if meta:
                tasks.append(self._load_plugin_impl(plugin_dir, meta))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 5. Collect results
        for plugin_dir, result in zip(plugin_dirs, results):
            if isinstance(result, Exception):
                self._failed_plugins[plugin_dir.name] = str(result)
            elif result:
                self._loaded_plugins[result['name']] = result

        return self._loaded_plugins

    async def load_plugin(self, plugin_name: str, **kwargs) -> Optional[Any]:
        """
        Load single plugin by name

        Args:
            plugin_name: Name of the plugin to load
            **kwargs: Additional arguments

        Returns:
            Optional[Any]: Plugin info or None if failed
        """
        # 1. Get plugin metadata
        meta = await self._repository.get_by_name(plugin_name)
        if not meta:
            return None

        if not meta.enabled:
            return None

        # 2. Find plugin directory
        plugin_dir = self._plugins_root / plugin_name
        if not plugin_dir.exists():
            return None

        # 3. Load plugin
        try:
            result = await self._load_plugin_impl(plugin_dir, meta)
            if result:
                self._loaded_plugins[plugin_name] = result
            return result
        except Exception as e:
            self._failed_plugins[plugin_name] = str(e)
            return None

    async def _load_plugin_impl(
        self,
        plugin_dir: Path,
        meta: PluginMetadata
    ) -> Optional[Dict[str, Any]]:
        """
        Internal plugin loading implementation

        Args:
            plugin_dir: Plugin directory path
            meta: Plugin metadata

        Returns:
            Optional[Dict[str, Any]]: Plugin info or None
        """
        # 1. Validate plugin directory
        validation = self._validator.validate_plugin_directory(plugin_dir)
        if not validation.is_valid:
            raise ValueError(f"Plugin validation failed: {validation.error_message}")

        # 2. Scan plugin structure
        scan_result = self._discovery.scan_plugin(plugin_dir)

        # 3. Parse functions based on plugin type
        functions = []

        if scan_result.has_python and scan_result.python_file:
            python_parser = self._parser_registry.get_parser('python')
            if python_parser:
                python_funcs = await python_parser.parse(scan_result.python_file)
                functions.extend(python_funcs)

        if scan_result.has_config and scan_result.config_file:
            config_parser = self._parser_registry.get_parser('config')
            if config_parser:
                config_funcs = await config_parser.parse(scan_result.config_file)
                functions.extend(config_funcs)

        for script_file in scan_result.script_files:
            shell_parser = self._parser_registry.get_parser('shell')
            if shell_parser:
                shell_funcs = await shell_parser.parse(script_file)
                functions.extend(shell_funcs)

        # 4. Build plugin info
        return {
            'name': meta.name,
            'version': meta.version,
            'author': meta.author,
            'description': meta.description,
            'enabled': meta.enabled,
            'priority': meta.priority,
            'category': meta.category,
            'plugin_type': scan_result.plugin_type.value,
            'plugin_dir': str(plugin_dir),
            'functions': functions,
            'metadata': meta,
        }

    def get_loaded_plugins(self) -> Dict[str, Any]:
        """Get all loaded plugins"""
        return self._loaded_plugins.copy()

    def get_failed_plugins(self) -> Dict[str, str]:
        """Get all failed plugins"""
        return self._failed_plugins.copy()

    def clear(self) -> None:
        """Clear loaded plugins cache"""
        self._loaded_plugins.clear()
        self._failed_plugins.clear()


__all__ = ['PluginLoader']
