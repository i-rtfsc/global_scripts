"""
PluginDisableCommand - 禁用插件命令
"""

from typing import List

from .base import Command
from ...core.config_manager import CommandResult


class PluginDisableCommand(Command):
    """禁用插件命令"""

    @property
    def name(self) -> str:
        return "plugin:disable"

    @property
    def aliases(self) -> List[str]:
        return []

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.plugin_disable_help")

    async def execute(self, args: List[str]) -> CommandResult:
        """执行禁用插件"""
        if not args:
            return CommandResult(
                success=False,
                error=self.i18n.get_message('errors.plugin_name_required'),
                exit_code=self.constants.exit_invalid_arguments
            )

        plugin_name = args[0]

        # Check if adapter has async method
        if hasattr(self.plugin_manager, 'disable_plugin_async'):
            return await self.plugin_manager.disable_plugin_async(plugin_name)
        else:
            # Fallback to sync method
            return self.plugin_manager.disable_plugin(plugin_name)
