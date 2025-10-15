"""
Status Command - 系统状态检查
"""

from typing import List

from .base import Command
from ...core.config_manager import CommandResult
from ...cli.system_commands import SystemCommands
from ...core.logger import get_logger
from ...utils.logging_utils import correlation_id, duration

logger = get_logger(tag="CLI.COMMANDS.STATUS", name=__name__)


class StatusCommand(Command):
    """状态命令"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 复用 SystemCommands 的实现
        self.system_commands = SystemCommands(
            self.config_manager,
            self.plugin_manager,
            chinese=self.i18n.current_language == 'zh'
        )

    @property
    def name(self) -> str:
        return "status"

    @property
    def aliases(self) -> List[str]:
        return ["状态"]

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.status_description")

    async def execute(self, args: List[str]) -> CommandResult:
        """显示系统状态"""
        from time import monotonic
        cid = correlation_id()
        start_ts = monotonic()
        logger.debug(f"cid={cid} status.enter")

        try:
            result = await self.system_commands.system_status()
            took = duration(start_ts)
            logger.debug(f"cid={cid} status.exit took_ms={took}")
            return result
        except Exception as e:
            took = duration(start_ts)
            logger.error(f"cid={cid} status.error took_ms={took} error={type(e).__name__}: {e}")
            return CommandResult(
                success=False,
                error=str(e),
                exit_code=self.constants.EXIT_EXECUTION_ERROR
            )
