"""
Version Command - 显示版本信息
"""

from typing import List

from .base import SimpleCommand
from ...core.config_manager import CommandResult


class VersionCommand(SimpleCommand):
    """版本命令"""

    @property
    def name(self) -> str:
        return "version"

    @property
    def aliases(self) -> List[str]:
        return ["--version", "-v", "版本"]

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.version_description")

    def _execute(self, args: List[str]) -> CommandResult:
        """显示版本信息"""
        version = self.constants.PROJECT_VERSION
        version_text = f"{self.constants.PROJECT_NAME} v{version}"
        return CommandResult(
            success=True,
            message=self.i18n.get_message("commands.version"),
            output=version_text
        )
