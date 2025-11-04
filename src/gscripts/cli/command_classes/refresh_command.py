"""
RefreshCommand - 系统刷新命令
重新生成补全脚本、环境脚本和路由索引
"""

from typing import List
from pathlib import Path
import subprocess

from ...core.logger import get_logger
from .base import Command
from gscripts.models.result import CommandResult

logger = get_logger(tag="CLI.REFRESH", name=__name__)


class RefreshCommand(Command):
    """系统刷新命令 - 重新生成所有配置和脚本"""

    @property
    def name(self) -> str:
        return "refresh"

    @property
    def aliases(self) -> List[str]:
        return ["reload"]

    @property
    def help_text(self) -> str:
        return self.i18n.get_message("commands.refresh_help")

    async def execute(self, args: List[str]) -> CommandResult:
        """执行刷新"""
        try:
            logger.info(self.i18n.get_message("commands.refresh"))

            # 1. 重新生成补全
            await self._regenerate_completions()

            # 2. 生成 router index
            await self._generate_router_index()

            # 3. 重新生成 env 文件 (如果不存在)
            await self._regenerate_env_if_missing()

            # 4. 尝试 source env 文件
            result_msg = await self._source_env_file()

            return CommandResult(
                success=True,
                message=self.i18n.get_message("commands.command_success"),
                output=result_msg,
            )

        except Exception:
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed"),
                exit_code=self.constants.exit_execution_error,
            )

    async def _regenerate_completions(self):
        """重新生成补全脚本"""
        try:
            project_root = Path(__file__).resolve().parents[4]
            setup_py = project_root / "scripts" / "setup.py"

            if setup_py.exists():
                result = subprocess.run(
                    ["python3", str(setup_py), "--generate-completion", "--auto"],
                    cwd=project_root,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode != 0:
                    logger.warning(
                        f"Completion generation returned {result.returncode}"
                    )

        except subprocess.TimeoutExpired:
            logger.error(self.i18n.get_message("errors.timeout"))
        except Exception as e:
            logger.warning(f"Failed to regenerate completions: {e}")

    async def _generate_router_index(self):
        """生成 router index"""
        try:
            from ...router.indexer import build_router_index, write_router_index
            from ...infrastructure.persistence.plugin_loader import PluginLoader
            from ...infrastructure.persistence.plugin_repository import PluginRepository
            from ...infrastructure.filesystem.file_operations import RealFileSystem
            from pathlib import Path

            # Reload plugins from disk to ensure we have fresh data
            project_root = Path(__file__).resolve().parents[4]
            plugins_root = project_root / "plugins"
            custom_root = project_root / "custom"

            # Create filesystem and repository for system plugins
            filesystem = RealFileSystem()
            repository = PluginRepository(
                filesystem=filesystem, plugins_dir=plugins_root
            )

            # Load system plugins
            loader = PluginLoader(
                plugin_repository=repository, plugins_root=plugins_root
            )
            plugins = await loader.load_all_plugins()

            # Load custom plugins if directory exists
            if custom_root.exists():
                custom_repository = PluginRepository(
                    filesystem=filesystem, plugins_dir=custom_root
                )
                custom_loader = PluginLoader(
                    plugin_repository=custom_repository, plugins_root=custom_root
                )
                custom_plugins = await custom_loader.load_all_plugins()
                plugins.update(custom_plugins)

            # 构建 router index
            index = build_router_index(plugins)

            # 写入 router index
            write_router_index(index)

        except Exception as e:
            logger.warning(f"Failed to generate router index: {e}")

    async def _regenerate_env_if_missing(self):
        """如果 env 文件不存在，重新生成"""
        try:
            project_root = Path(__file__).resolve().parents[4]

            # 检测当前 shell
            from ...utils.shell_utils import detect_current_shell

            shell = detect_current_shell()

            if shell == "fish":
                env_file_name = "env.fish"
            else:
                env_file_name = self.constants.env_sh_file_name

            env_path = project_root / env_file_name

            # 只有当文件不存在时才生成
            if not env_path.exists():
                setup_py = project_root / "scripts" / "setup.py"
                if setup_py.exists():
                    subprocess.run(
                        ["python3", str(setup_py), "--generate-env"],
                        cwd=project_root,
                        capture_output=True,
                        timeout=30,
                    )

        except Exception as e:
            logger.warning(f"Failed to regenerate env file: {e}")

    async def _source_env_file(self) -> str:
        """尝试 source env 文件"""
        try:
            project_root = Path(__file__).resolve().parents[4]

            from ...utils.shell_utils import detect_current_shell

            shell = detect_current_shell()

            if shell == "fish":
                env_file_name = "env.fish"
            else:
                env_file_name = self.constants.env_sh_file_name

            env_path = project_root / env_file_name

            if not env_path.exists():
                return self.i18n.get_message("setup.source_instruction")

            # 尝试 source
            if shell == "fish":
                source_cmd = f"source {env_path}"
            else:
                source_cmd = f"source {env_path}"

            result = subprocess.run(
                [
                    shell if shell != "unknown" else "bash",
                    "-c",
                    f"{source_cmd} >/dev/null 2>&1 && echo OK",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                return self.i18n.get_message("commands.command_success")
            else:
                return self.i18n.get_message("setup.source_instruction")

        except Exception:
            return self.i18n.get_message("setup.source_instruction")
