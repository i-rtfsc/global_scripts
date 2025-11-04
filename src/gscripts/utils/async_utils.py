#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 异步工具函数
提供异步操作的便捷工具，仅使用标准库
"""
import asyncio
import concurrent.futures
from typing import Any, Callable, Coroutine, List, Optional, Dict
from pathlib import Path
from functools import wraps


from ..core.logger import get_logger

# Module-level logger
logger = get_logger(tag="UTILS.ASYNC_UTILS", name=__name__)


class AsyncFileUtils:
    """异步文件操作工具类 - 使用标准库实现"""

    @staticmethod
    async def read_text(file_path: Path, encoding: str = "utf-8") -> str:
        """异步读取文本文件"""
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor, lambda: file_path.read_text(encoding=encoding)
            )

    @staticmethod
    async def write_text(
        file_path: Path, content: str, encoding: str = "utf-8"
    ) -> None:
        """异步写入文本文件"""
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(
                executor, lambda: file_path.write_text(content, encoding=encoding)
            )

    @staticmethod
    async def exists(file_path: Path) -> bool:
        """异步检查文件是否存在"""
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(executor, lambda: file_path.exists())


class AsyncUtils:
    """异步工具类"""

    @staticmethod
    async def run_with_timeout(coro: Coroutine, timeout: float = 30.0) -> Any:
        """在超时时间内运行协程"""
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError(f"操作超时 ({timeout}秒)")

    @staticmethod
    async def gather_with_limit(
        coroutines: List[Coroutine], limit: int = 10
    ) -> List[Any]:
        """限制并发数量的gather操作"""
        semaphore = asyncio.Semaphore(limit)

        async def _limited_coro(coro):
            async with semaphore:
                return await coro

        limited_coroutines = [_limited_coro(coro) for coro in coroutines]
        return await asyncio.gather(*limited_coroutines, return_exceptions=True)

    @staticmethod
    async def retry_async(
        coro_func: Callable,
        max_retries: int = 3,
        delay: float = 1.0,
        backoff: float = 2.0,
        exceptions: tuple = (Exception,),
    ) -> Any:
        """异步重试装饰器"""
        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                if asyncio.iscoroutinefunction(coro_func):
                    return await coro_func()
                else:
                    return coro_func()
            except exceptions as e:
                last_exception = e
                if attempt < max_retries:
                    await asyncio.sleep(delay * (backoff**attempt))
                else:
                    break

        raise last_exception

    @staticmethod
    async def read_file_async(filepath: str, encoding: str = "utf-8") -> str:
        """异步读取文件"""
        try:
            async with aiofiles.open(filepath, "r", encoding=encoding) as f:
                return await f.read()
        except Exception as e:
            raise IOError(f"读取文件失败 {filepath}: {e}")

    @staticmethod
    async def write_file_async(
        filepath: str, content: str, encoding: str = "utf-8", append: bool = False
    ) -> None:
        """异步写入文件"""
        try:
            mode = "a" if append else "w"
            async with aiofiles.open(filepath, mode, encoding=encoding) as f:
                await f.write(content)
        except Exception as e:
            raise IOError(f"写入文件失败 {filepath}: {e}")

    @staticmethod
    async def copy_file_async(src: str, dst: str) -> None:
        """异步复制文件"""
        try:
            async with aiofiles.open(src, "rb") as src_file:
                content = await src_file.read()

            async with aiofiles.open(dst, "wb") as dst_file:
                await dst_file.write(content)
        except Exception as e:
            raise IOError(f"复制文件失败 {src} -> {dst}: {e}")

    @staticmethod
    async def execute_command_async(
        command: str, cwd: Optional[str] = None, timeout: float = 30.0
    ) -> Dict[str, Any]:
        """异步执行shell命令 - 使用统一的ProcessExecutor"""
        from ..utils.process_executor import get_process_executor

        try:
            executor = get_process_executor()
            result = await executor.execute_shell(command, timeout=timeout, cwd=cwd)

            return {
                "returncode": result.exit_code,
                "stdout": result.output,
                "stderr": result.error,
                "success": result.success,
            }

        except Exception as e:
            return {"returncode": -1, "stdout": "", "stderr": str(e), "success": False}

    @staticmethod
    async def batch_execute_async(
        commands: List[str], max_concurrent: int = 5, timeout: float = 30.0
    ) -> List[Dict[str, Any]]:
        """批量异步执行命令"""
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _execute_limited(cmd):
            async with semaphore:
                return await AsyncUtils.execute_command_async(cmd, timeout=timeout)

        tasks = [_execute_limited(cmd) for cmd in commands]
        return await asyncio.gather(*tasks, return_exceptions=True)


def async_retry(
    max_retries: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
):
    """异步重试装饰器"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await AsyncUtils.retry_async(
                lambda: func(*args, **kwargs),
                max_retries=max_retries,
                delay=delay,
                backoff=backoff,
                exceptions=exceptions,
            )

        return wrapper

    return decorator


def async_timeout(timeout: float = 30.0):
    """异步超时装饰器"""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await AsyncUtils.run_with_timeout(
                func(*args, **kwargs), timeout=timeout
            )

        return wrapper

    return decorator


class AsyncTaskManager:
    """异步任务管理器"""

    def __init__(self, max_concurrent: int = 10):
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.tasks: Dict[str, asyncio.Task] = {}
        self.results: Dict[str, Any] = {}

    async def add_task(self, name: str, coro: Coroutine) -> str:
        """添加任务"""
        if name in self.tasks:
            raise ValueError(f"任务 {name} 已存在")

        async def _limited_task():
            async with self.semaphore:
                return await coro

        task = asyncio.create_task(_limited_task())
        self.tasks[name] = task
        return name

    async def wait_for_task(self, name: str, timeout: Optional[float] = None) -> Any:
        """等待特定任务完成"""
        if name not in self.tasks:
            raise ValueError(f"任务 {name} 不存在")

        task = self.tasks[name]
        if timeout:
            result = await asyncio.wait_for(task, timeout=timeout)
        else:
            result = await task

        self.results[name] = result
        return result

    async def wait_all(self, timeout: Optional[float] = None) -> Dict[str, Any]:
        """等待所有任务完成"""
        if not self.tasks:
            return {}

        if timeout:
            done, pending = await asyncio.wait(
                self.tasks.values(), timeout=timeout, return_when=asyncio.ALL_COMPLETED
            )
            # 取消未完成的任务
            for task in pending:
                task.cancel()
        else:
            await asyncio.gather(*self.tasks.values(), return_exceptions=True)

        # 收集结果
        for name, task in self.tasks.items():
            if task.done():
                try:
                    self.results[name] = task.result()
                except Exception as e:
                    self.results[name] = e

        return self.results

    def cancel_task(self, name: str) -> bool:
        """取消任务"""
        if name in self.tasks:
            self.tasks[name].cancel()
            return True
        return False

    def cancel_all(self) -> int:
        """取消所有任务"""
        cancelled_count = 0
        for task in self.tasks.values():
            if not task.done():
                task.cancel()
                cancelled_count += 1
        return cancelled_count

    def get_status(self) -> Dict[str, str]:
        """获取所有任务状态"""
        status = {}
        for name, task in self.tasks.items():
            if task.done():
                if task.cancelled():
                    status[name] = "已取消"
                elif task.exception():
                    status[name] = f"错误: {task.exception()}"
                else:
                    status[name] = "完成"
            else:
                status[name] = "运行中"
        return status
