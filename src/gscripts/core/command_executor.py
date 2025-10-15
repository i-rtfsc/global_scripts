"""
命令执行器 - 负责安全高效地执行shell命令
重构版：使用 ProcessExecutor 作为底层执行器，专注于安全检查和并发控制
"""

import asyncio
import shlex
import time
from typing import List, Optional, Dict, Any, Union, Tuple
from pathlib import Path

from .config_manager import CommandResult
from .constants import GlobalConstants
from ..utils.i18n import get_i18n_manager
from ..utils.process_executor import get_process_executor, ProcessConfig

from ..core.logger import get_logger
from ..utils.logging_utils import (
    correlation_id, duration, safe_repr, format_exception
)

logger = get_logger(tag="CORE.COMMAND_EXECUTOR", name=__name__)


class CommandExecutor:
    """命令执行器 - 安全的异步shell命令执行

    职责：
    1. 安全检查（危险命令、模式、命令长度）
    2. 并发控制（信号量限制）
    3. 参数安全处理（shlex.quote）
    4. 委托实际执行给 ProcessExecutor
    """

    def __init__(self, max_concurrent: int = None, default_timeout: int = None):
        """
        初始化命令执行器

        Args:
            max_concurrent: 最大并发执行数
            default_timeout: 默认超时时间(秒)
        """
        self.constants = GlobalConstants()
        self.max_concurrent = max_concurrent or self.constants.MAX_CONCURRENT_COMMANDS
        self.default_timeout = default_timeout or self.constants.DEFAULT_TIMEOUT
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        self.i18n = get_i18n_manager()

        # 使用 ProcessExecutor 作为底层执行器
        self.process_executor = get_process_executor()

        # 使用常量中的安全命令列表
        self.allowed_commands = set(self.constants.SAFE_COMMANDS)

        # 使用常量中的危险命令和模式
        self.dangerous_commands = set(self.constants.DANGEROUS_COMMANDS)
        self.dangerous_patterns = self.constants.FORBIDDEN_PATTERNS

    async def execute(
        self,
        command: Union[str, List[str]],
        args: List[str] = None,
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        capture_output: bool = True,
        shell: bool = False,
        skip_security_check: bool = False
    ) -> CommandResult:
        """
        执行命令（带安全检查和并发控制）

        Args:
            command: 命令或命令列表
            args: 命令参数
            timeout: 超时时间
            cwd: 工作目录
            env: 环境变量
            capture_output: 是否捕获输出
            shell: 是否使用shell执行（建议False）
            skip_security_check: 跳过安全检查（谨慎使用）

        Returns:
            CommandResult: 执行结果
        """
        start_time = time.time()
        timeout = timeout or self.default_timeout

        cid = correlation_id()
        logger.debug(
            f"cid={cid} exec.enter cmd={safe_repr(command)} args={safe_repr(args)} "
            f"timeout={timeout} cwd={cwd} shell={shell}"
        )

        # 构建完整命令
        full_command = self._build_command(command, args)

        # 安全检查（除非显式跳过）
        if not skip_security_check:
            security_ok, security_msg = self._security_check(full_command)
            if not security_ok:
                logger.warning(
                    f"cid={cid} exec.security_block cmd={' '.join(full_command)} "
                    f"reason={security_msg}"
                )
                return CommandResult(
                    success=False,
                    error=self.i18n.get_message('errors.command_not_safe', reason=security_msg),
                    exit_code=self.constants.EXIT_SECURITY_VIOLATION
                )

        # 并发控制
        async with self.semaphore:
            # 委托给 ProcessExecutor 执行
            config = ProcessConfig(
                timeout=timeout,
                cwd=cwd,
                env=env,
                capture_output=capture_output,
                shell=shell
            )

            try:
                if shell:
                    # Shell 执行
                    cmd_str = full_command[0] if isinstance(full_command, list) else full_command
                    result = await self.process_executor.execute_shell(cmd_str, config)
                else:
                    # 直接执行
                    result = await self.process_executor.execute(full_command, config)

                elapsed = time.time() - start_time
                logger.debug(
                    f"cid={cid} exec.complete success={result.success} "
                    f"exit_code={result.exit_code} elapsed_sec={elapsed:.2f}"
                )

                return result

            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(
                    f"cid={cid} exec.error elapsed_sec={elapsed:.2f} "
                    f"error={type(e).__name__}: {e}"
                )
                return CommandResult(
                    success=False,
                    error=f"执行失败: {format_exception(e)}",
                    exit_code=self.constants.EXIT_EXECUTION_ERROR
                )

    def _build_command(
        self,
        command: Union[str, List[str]],
        args: List[str] = None
    ) -> List[str]:
        """
        构建完整命令列表

        Args:
            command: 命令或命令列表
            args: 参数列表

        Returns:
            List[str]: 完整的命令列表
        """
        if isinstance(command, str):
            if args:
                # 安全地添加参数
                safe_args = [shlex.quote(arg) for arg in args]
                return [command] + safe_args
            else:
                return shlex.split(command)
        else:
            return command + (args or [])

    def _security_check(self, command: List[str]) -> Tuple[bool, str]:
        """
        安全检查

        Args:
            command: 命令列表

        Returns:
            Tuple[bool, str]: (是否安全, 原因)
        """
        if not command:
            return False, "空命令"

        # 检查命令长度
        cmd_str = ' '.join(command)
        if len(cmd_str) > self.constants.MAX_COMMAND_LENGTH:
            return False, f"命令过长 (>{self.constants.MAX_COMMAND_LENGTH}字符)"

        # 获取基础命令
        base_command = command[0].split('/')[-1]  # 去掉路径

        # 检查危险命令
        if base_command in self.dangerous_commands:
            return False, f"危险命令: {base_command}"

        # 检查危险模式
        cmd_lower = cmd_str.lower()
        for pattern in self.dangerous_patterns:
            if pattern in cmd_lower:
                return False, f"危险模式: {pattern}"

        return True, ""

    async def execute_safe(
        self,
        command: Union[str, List[str]],
        args: List[str] = None,
        **kwargs
    ) -> CommandResult:
        """
        安全执行命令（仅允许白名单命令）

        Args:
            command: 命令
            args: 参数
            **kwargs: 其他参数

        Returns:
            CommandResult: 执行结果
        """
        # 检查是否在白名单中
        base_cmd = command[0] if isinstance(command, list) else command.split()[0]
        base_cmd = base_cmd.split('/')[-1]  # 去掉路径

        if base_cmd not in self.allowed_commands:
            cid = correlation_id()
            logger.warning(
                f"cid={cid} exec_safe.blocked cmd={base_cmd} "
                f"not in whitelist"
            )
            return CommandResult(
                success=False,
                error=self.i18n.get_message(
                    'errors.command_not_allowed',
                    command=base_cmd
                ),
                exit_code=self.constants.EXIT_SECURITY_VIOLATION
            )

        return await self.execute(command, args, **kwargs)

    @property
    def running_processes(self) -> Dict[str, Any]:
        """获取运行中的进程"""
        return self.process_executor.get_running_processes()

    def kill_all(self):
        """终止所有运行中的进程"""
        self.process_executor.kill_all()


# 全局单例
_global_executor = None


def get_command_executor() -> CommandExecutor:
    """获取全局命令执行器单例"""
    global _global_executor
    if _global_executor is None:
        _global_executor = CommandExecutor()
    return _global_executor
