"""
Help Command - 显示帮助信息
"""

from typing import List

from .base import SimpleCommand
from gscripts.models.result import CommandResult


class HelpCommand(SimpleCommand):
    """帮助命令"""

    @property
    def name(self) -> str:
        return "help"

    @property
    def aliases(self) -> List[str]:
        return ["--help", "-h", "帮助"]

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.help_description")

    def _execute(self, args: List[str]) -> CommandResult:
        """显示帮助信息"""
        help_text = self.formatter.format_help_usage()
        return CommandResult(
            success=True,
            message=self.i18n.get_message("commands.help"),
            output=help_text,
        )
