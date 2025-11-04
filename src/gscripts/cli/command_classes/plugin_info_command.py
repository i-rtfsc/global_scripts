"""
Plugin Info Command
Uses PluginService with dependency injection
"""

import json
from typing import List, Dict, Any, Optional

from .base import Command
from gscripts.models.result import CommandResult
from ...core.constants import GlobalConstants
from ...application.services import PluginService
from ...models.plugin import PluginMetadata


class PluginInfoCommand(Command):
    """
    Plugin Info Command using PluginService

    Uses dependency injection for better testability:
    - PluginService is injected
    - Easier to mock and test
    - Clean separation of concerns
    """

    def __init__(
        self,
        config_manager=None,
        plugin_manager=None,
        i18n=None,
        formatter=None,
        constants=None,
        chinese=True,
        plugin_service=None,
    ):
        """
        Initialize command with dependency injection

        Args:
            config_manager: Config manager (for backward compatibility)
            plugin_manager: Plugin manager (for backward compatibility)
            i18n: I18n manager
            formatter: Output formatter
            constants: Constants
            chinese: Use Chinese language
            plugin_service: Plugin service (optional, will be created if not provided)
        """
        super().__init__(
            config_manager=config_manager,
            plugin_manager=plugin_manager,
            formatter=formatter,
            i18n=i18n,
            constants=constants,
            chinese=chinese,
        )

        # Create plugin_service if not provided (for backward compatibility)
        if plugin_service is None:
            from ...infrastructure import get_container, configure_services
            from ...application.services import PluginService
            from pathlib import Path
            import os

            container = get_container()

            # Try to resolve, configure if needed
            try:
                plugin_service = container.resolve(PluginService)
            except KeyError:
                # Service not registered, configure now
                # Use GS_ROOT for plugins directory (development/installed location)
                gs_root = Path(os.environ.get("GS_ROOT", os.getcwd()))
                plugins_dir = gs_root / "plugins"
                config_path = gs_root / "gs.json"

                # Try to use router.json cache from GS_HOME
                from ...core.constants import GlobalConstants

                router_cache_path = GlobalConstants.gs_home / "cache" / "router.json"

                configure_services(
                    container,
                    use_mocks=False,
                    plugins_dir=plugins_dir,
                    config_path=config_path,
                    router_cache_path=router_cache_path,
                )
                plugin_service = container.resolve(PluginService)

        self.plugin_service = plugin_service

    @property
    def name(self) -> str:
        return "plugin:info"

    @property
    def aliases(self) -> List[str]:
        return []

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.plugin_info_description")

    def _load_router_index(self) -> Dict[str, Any]:
        """从router index加载插件信息 (保持兼容性)"""
        try:
            gs_home = GlobalConstants.gs_home
            router_index_path = gs_home / "cache" / "router.json"

            if not router_index_path.exists():
                return {}

            with open(router_index_path, "r", encoding="utf-8") as f:
                index = json.load(f)

            return index.get("plugins", {})
        except Exception:
            return {}

    def _get_plugin_type_display(
        self, plugin_type: str = None, plugin_dir: str = ""
    ) -> str:
        """获取插件类型的显示文本

        Args:
            plugin_type: 插件类型 (hybrid/python/script/config/core)
            plugin_dir: 插件目录路径 (用于回退判断)
        """
        # 优先使用 plugin_type，从 i18n 获取本地化文本
        if plugin_type:
            # 标准化类型名称
            normalized_type = plugin_type.lower()
            if normalized_type == "shell":
                normalized_type = "script"
            elif normalized_type == "json":
                normalized_type = "config"

            # 从 plugin_implementation_types 获取本地化文本
            return self.i18n.get_message(
                f"plugin_implementation_types.{normalized_type}"
            )

        # 回退：基于路径判断，使用 plugin_source_types
        if "/examples/" in plugin_dir or plugin_dir.endswith("/examples"):
            return self.i18n.get_message("plugin_source_types.example")
        elif "/plugins/" in plugin_dir or plugin_dir.endswith("/plugins"):
            return self.i18n.get_message("plugin_source_types.system")
        elif "/custom/" in plugin_dir or plugin_dir.endswith("/custom"):
            return self.i18n.get_message("plugin_source_types.third_party")
        return self.i18n.get_message("plugin_implementation_types.unknown")

    def _build_commands_list(
        self, loaded_info: Optional[Dict[str, Any]], plugin_name: str
    ) -> List[Dict[str, Any]]:
        """Build commands list from loaded plugin info"""
        if not loaded_info:
            return []

        language = "zh" if self.chinese else "en"
        options_text = "[options]" if language == "en" else "[选项]"
        commands = []

        # Try router.json format first (dict with command details)
        router_commands = loaded_info.get("commands", {})
        if isinstance(router_commands, dict) and router_commands:
            for cmd_key, cmd_info in router_commands.items():
                # Get localized description
                cmd_desc_data = cmd_info.get("description", {})
                if isinstance(cmd_desc_data, dict):
                    cmd_description = cmd_desc_data.get(
                        language, cmd_desc_data.get("zh", "")
                    )
                else:
                    cmd_description = str(cmd_desc_data)

                # Get usage
                usage = cmd_info.get("usage", "")
                if not usage:
                    usage = f"gs {plugin_name} {cmd_key} {options_text}"

                commands.append(
                    {
                        "command": f"gs {plugin_name} {cmd_key}",
                        "shell_function": cmd_info.get("name", cmd_key),
                        "subplugin": cmd_info.get("subplugin", ""),
                        "plugin_type": cmd_info.get("kind", "unknown"),
                        "usage": usage,
                        "description": cmd_description,
                    }
                )
            return commands

        # Fallback: old format (functions dict)
        functions = loaded_info.get("functions", {})
        if functions:
            for func_name, func_obj in functions.items():
                func_description = ""
                if isinstance(func_obj, dict):
                    func_desc = func_obj.get("description", "")
                    if isinstance(func_desc, dict):
                        func_description = func_desc.get(
                            language, func_desc.get("zh", func_desc.get("en", ""))
                        )
                    else:
                        func_description = str(func_desc)

                command_str = f"gs {plugin_name} {func_name}"
                commands.append(
                    {
                        "command": command_str,
                        "shell_function": func_name,
                        "subplugin": "",
                        "plugin_type": loaded_info.get("plugin_type", "unknown"),
                        "usage": f"{command_str} {options_text}",
                        "description": func_description,
                    }
                )

        return commands

    def _metadata_to_display_info(
        self, meta: PluginMetadata, loaded_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert PluginMetadata to display info"""
        language = "zh" if self.chinese else "en"

        # Get localized description
        description = meta.get_description(language)

        # Get plugin type and directory from loaded info
        plugin_type = loaded_info.get("type", "") if loaded_info else ""
        plugin_dir = loaded_info.get("plugin_dir", "") if loaded_info else ""
        type_display = self._get_plugin_type_display(plugin_type, plugin_dir)

        # Build commands list
        commands = self._build_commands_list(loaded_info, meta.name)

        return {
            "name": meta.name,
            "version": meta.version,
            "author": meta.author,
            "description": description,
            "enabled": meta.enabled,
            "type": type_display,
            "priority": meta.priority,
            "directory": plugin_dir or "N/A",
            "homepage": meta.homepage,
            "license": meta.license,
            "category": meta.category,
            "keywords": meta.keywords,
            "commands": commands,
        }

    async def execute(self, args: List[str]) -> CommandResult:
        """Display plugin detailed information using PluginService"""
        try:
            if not args:
                return CommandResult(
                    success=False,
                    error=self.i18n.get_message("errors.missing_plugin_name"),
                    exit_code=self.constants.exit_misuse,
                )

            plugin_name = args[0]

            # Use PluginService to get plugin metadata
            metadata = await self.plugin_service.get_plugin_metadata(plugin_name)

            if not metadata:
                return CommandResult(
                    success=False,
                    error=self.i18n.get_message("errors.plugin_not_found"),
                    exit_code=self.constants.exit_plugin_not_found,
                )

            # Load router index for additional info
            router_plugins = self._load_router_index()

            # Get loaded plugin info for command details (fallback)
            loaded_plugins = self.plugin_service.get_loaded_plugins()

            # Prefer router.json data, fallback to loaded_plugins
            plugin_info_data = (
                router_plugins.get(plugin_name) or loaded_plugins.get(plugin_name) or {}
            )

            # Convert to display format
            plugin_info = self._metadata_to_display_info(metadata, plugin_info_data)

            # Use formatter to print (same as before)
            self.formatter.print_plugin_info(plugin_info)

            return CommandResult(
                success=True,
                message=self.i18n.get_message("commands.plugin_info"),
                output="",
            )

        except Exception as e:
            return CommandResult(
                success=False,
                error=f"Failed to get plugin info: {str(e)}",
                exit_code=self.constants.exit_general_error,
            )


# Factory function to create command with DI
def create_plugin_info_command(
    plugin_service: PluginService, **kwargs
) -> PluginInfoCommand:
    """
    Factory function to create PluginInfoCommand with injected dependencies

    Usage:
        from gscripts.infrastructure import get_container
        from gscripts.application.services import PluginService

        container = get_container()
        plugin_service = container.resolve(PluginService)

        command = create_plugin_info_command(
            plugin_service=plugin_service,
            formatter=formatter,
            i18n=i18n,
            chinese=True
        )

        result = await command.execute(['plugin_name'])
    """
    return PluginInfoCommand(plugin_service=plugin_service, **kwargs)
