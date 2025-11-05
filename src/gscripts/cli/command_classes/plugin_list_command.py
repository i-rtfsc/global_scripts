"""
Plugin List Command
Uses PluginService with dependency injection
"""

import json
from typing import List, Dict, Any, Optional

from .base import Command
from gscripts.models.result import CommandResult
from ...core.constants import GlobalConstants
from ...models.plugin import PluginMetadata


class PluginListCommand(Command):
    """
    Plugin List Command using PluginService

    Uses dependency injection for better testability:
    - PluginService is injected
    - Easier to mock and test
    - Clean separation of concerns
    """

    def __init__(
        self,
        config_manager,
        plugin_service,
        plugin_executor,
        i18n,
        formatter,
        constants,
        chinese=True,
    ):
        """
        Initialize command with dependency injection

        Args:
            config_manager: Config manager
            plugin_service: Plugin service
            plugin_executor: Plugin executor
            i18n: I18n manager
            formatter: Output formatter
            constants: Constants
            chinese: Use Chinese language
        """
        super().__init__(
            config_manager,
            plugin_service,
            plugin_executor,
            i18n,
            formatter,
            constants,
            chinese,
        )

    @property
    def name(self) -> str:
        return "plugin:list"

    @property
    def aliases(self) -> List[str]:
        return ["plugins"]

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.plugin_list_description")

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

    def _metadata_to_display_info(
        self, meta: PluginMetadata, loaded_info: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Convert PluginMetadata to display info"""
        language = "zh" if self.chinese else "en"

        # Get localized description
        description = meta.get_description(language)

        # Get plugin type and directory from loaded_info
        plugin_type = loaded_info.get("type", "") if loaded_info else ""
        plugin_dir = loaded_info.get("plugin_dir", "") if loaded_info else ""
        type_display = self._get_plugin_type_display(plugin_type, plugin_dir)

        # Get command count - check multiple possible fields
        command_count = 0
        if loaded_info:
            # Try 'commands' field (from router.json - dict or int)
            commands = loaded_info.get("commands", {})
            if isinstance(commands, dict):
                command_count = len(commands)
            elif isinstance(commands, int):
                command_count = commands
            else:
                # Fallback to 'functions' field
                command_count = len(loaded_info.get("functions", []))

        return {
            "name": meta.name,
            "version": meta.version,
            "type": type_display,
            "priority": meta.priority,
            "command_count": command_count,
            "description": description,
            "enabled": meta.enabled,
        }

    async def execute(self, args: List[str]) -> CommandResult:
        """Display plugin list using PluginService"""
        try:
            # Use plugin_service to list all plugins
            all_plugins = await self.plugin_service.list_all_plugins()

            if not all_plugins:
                return CommandResult(
                    success=True,
                    message=self.i18n.get_message("plugin_list.no_plugins"),
                    output="No plugins found",
                )

            # Load router index for additional info (type, commands, etc.)
            router_plugins = self._load_router_index()

            # Get loaded plugin info for command counts (fallback)
            loaded_plugins = self.plugin_service.get_loaded_plugins()

            # Separate enabled and disabled plugins
            enabled_plugins = []
            disabled_plugins = []

            for meta in all_plugins:
                # Prefer router.json data, fallback to loaded_plugins
                plugin_info = (
                    router_plugins.get(meta.name) or loaded_plugins.get(meta.name) or {}
                )
                display_info = self._metadata_to_display_info(meta, plugin_info)

                if meta.enabled:
                    enabled_plugins.append(display_info)
                else:
                    disabled_plugins.append(display_info)

            # Sort by priority then name
            enabled_plugins.sort(key=lambda x: (x["priority"], x["name"]))
            disabled_plugins.sort(key=lambda x: (x["priority"], x["name"]))

            # Use formatter to print (same as before)
            self.formatter.print_plugin_list(enabled_plugins, disabled_plugins)

            return CommandResult(
                success=True,
                message=self.i18n.get_message("commands.plugin_list"),
                output="",
            )

        except Exception as e:
            return CommandResult(
                success=False,
                error=f"Failed to list plugins: {str(e)}",
                exit_code=self.constants.exit_general_error,
            )
