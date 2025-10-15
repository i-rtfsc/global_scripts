"""
PluginEnableCommand - 启用插件命令
"""

from typing import List

from .base import SimpleCommand
from ...core.config_manager import CommandResult


class PluginEnableCommand(SimpleCommand):
    """启用插件命令"""

    @property
    def name(self) -> str:
        return "plugin:enable"

    @property
    def aliases(self) -> List[str]:
        return []

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.plugin_enable_help")

    def _execute(self, args: List[str]) -> CommandResult:
        """执行启用插件"""
        if not args:
            return CommandResult(
                success=False,
                error=self.i18n.get_message('errors.plugin_name_required'),
                exit_code=self.constants.EXIT_INVALID_ARGUMENTS
            )

        plugin_name = args[0]
        return self.plugin_manager.enable_plugin(plugin_name)
