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
        self._parser_registry.register(PythonFunctionParser(), name='python')
        self._parser_registry.register(ShellFunctionParser(), name='shell')
        self._parser_registry.register(ConfigFunctionParser(), name='config')

    async def load_all_plugins(self, include_examples: bool = False) -> Dict[str, Any]:
        """
        Load all plugins

        Args:
            include_examples: Whether to include example plugins

        Returns:
            Dict[str, Any]: Loaded plugins dictionary
        """
        from ...core.logger import get_logger
        logger = get_logger(tag="INFRA.LOADER", name=__name__)

        # 1. Get plugin metadata from repository
        plugins_meta = await self._repository.get_all()
        logger.info(f"Repository returned {len(plugins_meta)} plugins metadata")

        # 2. Filter enabled plugins
        enabled_plugins = [p for p in plugins_meta if p.enabled]
        logger.info(f"Found {len(enabled_plugins)} enabled plugins: {[p.name for p in enabled_plugins]}")

        # 3. Discover plugin directories
        plugin_dirs = self._discovery.discover_all_plugins(include_examples)
        logger.info(f"Discovered {len(plugin_dirs)} plugin directories: {[d.name for d in plugin_dirs]}")

        # 4. Load plugins in parallel
        # Track (plugin_dir, task) pairs to maintain alignment
        task_pairs = []
        for plugin_dir in plugin_dirs:
            plugin_name = plugin_dir.name

            # Find matching metadata
            meta = next((p for p in enabled_plugins if p.name == plugin_name), None)

            if meta:
                task_pairs.append((plugin_dir, self._load_plugin_impl(plugin_dir, meta)))
            else:
                logger.debug(f"No metadata found for {plugin_name}, skipping")

        logger.info(f"Created {len(task_pairs)} load tasks")

        # Extract tasks for gather
        tasks = [task for _, task in task_pairs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 5. Collect results (now properly aligned)
        for (plugin_dir, _), result in zip(task_pairs, results):
            if isinstance(result, Exception):
                self._failed_plugins[plugin_dir.name] = str(result)
                logger.error(f"Failed to load {plugin_dir.name}: {result}")
            elif result:
                self._loaded_plugins[result['name']] = result
                logger.debug(f"Successfully loaded {result['name']}")

        logger.info(f"Final: loaded {len(self._loaded_plugins)} plugins, failed {len(self._failed_plugins)}")
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
        scan_result = self._discovery.scan_plugin_directory(plugin_dir)

        # 3. Find and scan subplugins
        subplugins = self._discovery.find_subplugins(plugin_dir)

        # 4. Parse functions based on plugin type
        functions = []
        plugin_name = meta.name

        # Parse main plugin files
        if scan_result.has_python and scan_result.python_file:
            python_parser = self._parser_registry.get('python')
            if python_parser:
                python_funcs = await python_parser.parse(
                    scan_result.python_file,
                    plugin_name,
                    ""  # subplugin_name - empty for main plugin
                )
                functions.extend(python_funcs)

        if scan_result.has_config and scan_result.config_files:
            config_parser = self._parser_registry.get('config')
            if config_parser:
                # Parse all config files (usually commands.json)
                for config_file in scan_result.config_files:
                    if config_file.name == 'commands.json':  # Skip plugin.json metadata
                        config_funcs = await config_parser.parse(
                            config_file,
                            plugin_name,
                            ""  # subplugin_name - empty for main plugin
                        )
                        functions.extend(config_funcs)

        if scan_result.has_scripts and scan_result.script_files:
            shell_parser = self._parser_registry.get('shell')
            if shell_parser:
                for script_file in scan_result.script_files:
                    # Detect subplugin name from file path
                    # e.g., plugins/identity/anyrouter/plugin.sh -> subplugin = "anyrouter"
                    relative_path = script_file.relative_to(plugin_dir)
                    parts = relative_path.parts
                    subplugin_name = parts[0] if len(parts) > 1 and parts[0] != script_file.name else ""

                    shell_funcs = await shell_parser.parse(
                        script_file,
                        plugin_name,
                        subplugin_name
                    )
                    functions.extend(shell_funcs)

        # Parse subplugins
        for subplugin_dir in subplugins:
            subplugin_name = subplugin_dir.name
            subplugin_scan = self._discovery.scan_plugin_directory(subplugin_dir)

            # Parse subplugin Python files
            if subplugin_scan.has_python and subplugin_scan.python_file:
                python_parser = self._parser_registry.get('python')
                if python_parser:
                    python_funcs = await python_parser.parse(
                        subplugin_scan.python_file,
                        plugin_name,
                        subplugin_name
                    )
                    functions.extend(python_funcs)

            # Parse subplugin config files
            if subplugin_scan.has_config and subplugin_scan.config_files:
                config_parser = self._parser_registry.get('config')
                if config_parser:
                    for config_file in subplugin_scan.config_files:
                        if config_file.name == 'commands.json':
                            config_funcs = await config_parser.parse(
                                config_file,
                                plugin_name,
                                subplugin_name
                            )
                            functions.extend(config_funcs)

            # Parse subplugin shell scripts
            if subplugin_scan.has_scripts and subplugin_scan.script_files:
                shell_parser = self._parser_registry.get('shell')
                if shell_parser:
                    for script_file in subplugin_scan.script_files:
                        shell_funcs = await shell_parser.parse(
                            script_file,
                            plugin_name,
                            subplugin_name
                        )
                        functions.extend(shell_funcs)

        # 4. Build plugin info
        # Convert functions list to dict (key = function name or subplugin-function for subplugins)
        from ...core.logger import get_logger
        from dataclasses import asdict
        logger = get_logger(tag="INFRA.LOADER", name=__name__)

        logger.info(f"Plugin {meta.name}: parsed {len(functions)} total functions")

        functions_dict = {}
        for func in functions:
            # For subplugin functions, use composite key: "subplugin function" (with space, like router.json)
            # For main plugin functions, use just the function name
            if func.subplugin and func.subplugin != meta.name:
                key = f"{func.subplugin} {func.name}"
            else:
                key = func.name

            # Convert FunctionInfo to dict for compatibility with executor
            func_dict = asdict(func)
            # Convert Path objects to strings
            for path_key in ['python_file', 'script_file', 'config_file', 'working_dir']:
                if path_key in func_dict and func_dict[path_key] is not None:
                    func_dict[path_key] = str(func_dict[path_key])
            # Convert FunctionType enum to string value
            if 'type' in func_dict and hasattr(func_dict['type'], 'value'):
                func_dict['type'] = func_dict['type'].value

            functions_dict[key] = func_dict
            logger.debug(f"Added function with key: {key} (subplugin: {func.subplugin})")

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
            'functions': functions_dict,  # Dict instead of list
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
