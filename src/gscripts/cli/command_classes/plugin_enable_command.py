"""
PluginEnableCommand - 启用插件命令
"""

from typing import List

from .base import Command
from gscripts.models.result import CommandResult


class PluginEnableCommand(Command):
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

    async def execute(self, args: List[str]) -> CommandResult:
        """执行启用插件"""
        if not args:
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.plugin_name_required"),
                exit_code=self.constants.exit_invalid_arguments,
            )

        plugin_name = args[0]

        # Use plugin_service to enable plugin
        success = await self.plugin_service.enable_plugin(plugin_name)

        if success:
            return CommandResult(
                success=True,
                output=f"Plugin '{plugin_name}' enabled successfully",
                exit_code=0,
            )
        else:
            return CommandResult(
                success=False,
                error=f"Failed to enable plugin '{plugin_name}'",
                exit_code=1,
            )
