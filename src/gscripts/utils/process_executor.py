"""
统一的进程执行器
消除重复的subprocess创建代码
"""

import asyncio
import os
import signal
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from dataclasses import dataclass

from ..models import CommandResult
from ..core.logger import get_logger
from ..utils.logging_utils import correlation_id, duration


logger = get_logger(tag="UTILS.PROCESS_EXECUTOR", name=__name__)


@dataclass
class ProcessConfig:
    """进程配置"""

    timeout: int = 30
    cwd: Optional[Path] = None
    env: Optional[Dict[str, str]] = None
    capture_output: bool = True
    shell: bool = False


class ProcessExecutor:
    """统一的进程执行器

    提供一致的subprocess执行接口,避免代码重复
    """

    def __init__(self, default_timeout: int = 30):
        self.default_timeout = default_timeout
        self.running_processes: Dict[str, asyncio.subprocess.Process] = {}

    async def execute(
        self,
        command: Union[str, List[str]],
        config: Optional[ProcessConfig] = None,
        **kwargs,
    ) -> CommandResult:
        """执行命令

        Args:
            command: 命令字符串或命令列表
            config: 进程配置
            **kwargs: 额外的配置参数

        Returns:
            CommandResult: 执行结果
        """
        if config is None:
            config = ProcessConfig(timeout=self.default_timeout)

        # 允许通过kwargs覆盖config
        timeout = kwargs.get("timeout", config.timeout)
        cwd = kwargs.get("cwd", config.cwd)
        env = kwargs.get("env", config.env)
        capture_output = kwargs.get("capture_output", config.capture_output)

        cid = correlation_id()
        start_time = time.monotonic()

        # 准备命令
        if isinstance(command, str):
            cmd_list = [command]
            cmd_str = command
        else:
            cmd_list = command
            cmd_str = " ".join(command)

        logger.debug(f"cid={cid} Executing: {cmd_str}, timeout={timeout}")

        process = None
        process_id = None

        try:
            # 准备环境变量
            final_env = os.environ.copy()
            if env:
                final_env.update(env)

            # 准备输出捕获
            if capture_output:
                stdout = asyncio.subprocess.PIPE
                stderr = asyncio.subprocess.PIPE
            else:
                stdout = None
                stderr = None

            # 创建进程
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=final_env,
                preexec_fn=os.setsid if os.name == "posix" else None,
            )

            process_id = str(process.pid)
            self.running_processes[process_id] = process

            # 等待进程完成或超时
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )

                output = (
                    stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
                )
                error = (
                    stderr_data.decode("utf-8", errors="replace") if stderr_data else ""
                )

                elapsed = duration(start_time)

                result = CommandResult(
                    success=process.returncode == 0,
                    output=output,
                    error=error,
                    exit_code=process.returncode or 0,
                    execution_time=elapsed / 1000.0,  # 转换为秒
                    metadata={
                        "command": cmd_str,
                        "pid": process.pid,
                        "cwd": str(cwd) if cwd else None,
                    },
                )

                logger.debug(
                    f"cid={cid} Process completed: pid={process.pid}, "
                    f"exit_code={process.returncode}, duration_ms={elapsed}"
                )

                return result

            except asyncio.TimeoutError:
                # 超时处理
                await self._kill_process_group(process)

                elapsed = duration(start_time)
                logger.warning(
                    f"cid={cid} Process timeout: pid={process.pid}, "
                    f"timeout={timeout}s, duration_ms={elapsed}"
                )

                return CommandResult(
                    success=False,
                    error=f"命令执行超时 (>{timeout}秒)",
                    exit_code=-1,
                    execution_time=timeout,
                    metadata={"command": cmd_str, "timeout": True},
                )

        except Exception as e:
            elapsed = duration(start_time)
            logger.error(
                f"cid={cid} Process execution failed: {type(e).__name__}: {e}, "
                f"duration_ms={elapsed}"
            )

            if process and process.returncode is None:
                await self._kill_process_group(process)

            return CommandResult(
                success=False,
                error=f"命令执行失败: {str(e)}",
                exit_code=-1,
                execution_time=elapsed / 1000.0,
                metadata={"command": cmd_str, "exception": str(e)},
            )

        finally:
            # 清理进程引用
            if process_id and process_id in self.running_processes:
                del self.running_processes[process_id]

    async def execute_shell(
        self, command: str, config: Optional[ProcessConfig] = None, **kwargs
    ) -> CommandResult:
        """执行Shell命令

        Args:
            command: Shell命令字符串
            config: 进程配置
            **kwargs: 额外的配置参数

        Returns:
            CommandResult: 执行结果
        """
        if config is None:
            config = ProcessConfig(timeout=self.default_timeout)

        config.shell = True

        cid = correlation_id()
        start_time = time.monotonic()

        logger.debug(f"cid={cid} Executing shell: {command}")

        timeout = kwargs.get("timeout", config.timeout)
        cwd = kwargs.get("cwd", config.cwd)
        env = kwargs.get("env", config.env)
        capture_output = kwargs.get("capture_output", config.capture_output)

        process = None
        process_id = None

        try:
            # 准备环境变量
            final_env = os.environ.copy()
            if env:
                final_env.update(env)

            # 准备输出捕获
            if capture_output:
                stdout = asyncio.subprocess.PIPE
                stderr = asyncio.subprocess.PIPE
            else:
                stdout = None
                stderr = None

            # 创建Shell进程
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=stdout,
                stderr=stderr,
                cwd=cwd,
                env=final_env,
                preexec_fn=os.setsid if os.name == "posix" else None,
            )

            process_id = str(process.pid)
            self.running_processes[process_id] = process

            # 等待进程完成或超时
            try:
                stdout_data, stderr_data = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )

                output = (
                    stdout_data.decode("utf-8", errors="replace") if stdout_data else ""
                )
                error = (
                    stderr_data.decode("utf-8", errors="replace") if stderr_data else ""
                )

                elapsed = duration(start_time)

                result = CommandResult(
                    success=process.returncode == 0,
                    output=output,
                    error=error,
                    exit_code=process.returncode or 0,
                    execution_time=elapsed / 1000.0,
                    metadata={
                        "command": command,
                        "pid": process.pid,
                        "cwd": str(cwd) if cwd else None,
                        "shell": True,
                    },
                )

                logger.debug(
                    f"cid={cid} Shell process completed: pid={process.pid}, "
                    f"exit_code={process.returncode}, duration_ms={elapsed}"
                )

                return result

            except asyncio.TimeoutError:
                await self._kill_process_group(process)

                elapsed = duration(start_time)
                logger.warning(
                    f"cid={cid} Shell process timeout: pid={process.pid}, "
                    f"timeout={timeout}s, duration_ms={elapsed}"
                )

                return CommandResult(
                    success=False,
                    error=f"Shell命令执行超时 (>{timeout}秒)",
                    exit_code=-1,
                    execution_time=timeout,
                    metadata={"command": command, "timeout": True, "shell": True},
                )

        except Exception as e:
            elapsed = duration(start_time)
            logger.error(
                f"cid={cid} Shell process execution failed: {type(e).__name__}: {e}, "
                f"duration_ms={elapsed}"
            )

            if process and process.returncode is None:
                await self._kill_process_group(process)

            return CommandResult(
                success=False,
                error=f"Shell命令执行失败: {str(e)}",
                exit_code=-1,
                execution_time=elapsed / 1000.0,
                metadata={"command": command, "exception": str(e), "shell": True},
            )

        finally:
            if process_id and process_id in self.running_processes:
                del self.running_processes[process_id]

    async def _kill_process_group(self, process: asyncio.subprocess.Process):
        """终止进程组"""
        cid = correlation_id()

        try:
            if process and process.returncode is None:
                if os.name == "posix":
                    # POSIX系统:终止整个进程组
                    try:
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                        await asyncio.sleep(2)
                        if process.returncode is None:
                            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    # Windows系统
                    process.terminate()
                    await asyncio.sleep(2)
                    if process.returncode is None:
                        process.kill()

                logger.debug(f"cid={cid} Process group killed: pid={process.pid}")

        except Exception as e:
            logger.warning(
                f"cid={cid} Failed to kill process: pid={getattr(process, 'pid', None)}, "
                f"error={type(e).__name__}: {e}"
            )

    def kill_all(self):
        """终止所有运行中的进程"""
        cid = correlation_id()
        logger.info(
            f"cid={cid} Killing all running processes: count={len(self.running_processes)}"
        )

        for process_id, process in list(self.running_processes.items()):
            try:
                if process.returncode is None:
                    if os.name == "posix":
                        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                    else:
                        process.terminate()
            except Exception as e:
                logger.warning(f"Failed to kill process {process_id}: {e}")

        self.running_processes.clear()

    def get_running_processes(self) -> Dict[str, Dict[str, Any]]:
        """获取运行中的进程信息"""
        result = {}
        for process_id, process in self.running_processes.items():
            result[process_id] = {
                "pid": process.pid,
                "returncode": process.returncode,
                "running": process.returncode is None,
            }
        return result


# 全局单例
_global_executor = None


def get_process_executor() -> ProcessExecutor:
    """获取全局进程执行器单例"""
    global _global_executor
    if _global_executor is None:
        _global_executor = ProcessExecutor()
    return _global_executor
