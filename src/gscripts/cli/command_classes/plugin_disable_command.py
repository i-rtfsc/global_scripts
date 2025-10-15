"""
PluginDisableCommand - 禁用插件命令
"""

from typing import List

from .base import SimpleCommand
from ...core.config_manager import CommandResult


class PluginDisableCommand(SimpleCommand):
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

    def _execute(self, args: List[str]) -> CommandResult:
        """执行禁用插件"""
        if not args:
            return CommandResult(
                success=False,
                error=self.i18n.get_message('errors.plugin_name_required'),
                exit_code=self.constants.EXIT_INVALID_ARGUMENTS
            )

        plugin_name = args[0]
        return self.plugin_manager.disable_plugin(plugin_name)
