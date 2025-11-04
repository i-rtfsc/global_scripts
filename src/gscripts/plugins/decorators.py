"""
插件装饰器系统
提供用于标记和增强插件函数的装饰器
支持四种插件类型：Python注解插件、配置文件插件、Shell脚本插件、混合插件
"""

import functools
import asyncio
import time
from dataclasses import dataclass, field
from typing import List, Callable, Any, Optional, Dict


from ..core.logger import get_logger

# Module-level logger
logger = get_logger(tag="PLUGINS.DECORATORS", name=__name__)


@dataclass
class FunctionMetadata:
    """插件函数元数据"""

    name: str
    description: str = ""
    usage: str = ""
    examples: List[str] = field(default_factory=list)
    args: List[Dict[str, Any]] = field(default_factory=list)  # 参数定义
    async_func: bool = False
    min_args: Optional[int] = None
    max_args: Optional[int] = None
    required_devices: bool = False
    timeout: int = 30
    cache_result: bool = False
    cache_ttl: int = 300  # 5分钟缓存
    permission_required: Optional[str] = None


# 全局函数缓存
_function_cache: Dict[str, Dict[str, Any]] = {}


def plugin_function(
    name: str,
    description: str = "",
    usage: str = "",
    examples: List[str] = None,
    args: List[Dict[str, Any]] = None,
    timeout: int = 30,
    cache_result: bool = False,
    cache_ttl: int = 300,
    permission_required: Optional[str] = None,
):
    """
    插件函数装饰器

    Args:
        name: 函数名称
        description: 函数描述
        usage: 使用方法
        examples: 使用示例
        args: 参数定义列表,每个参数包含:
            - name: 参数名称
            - type: 参数类型 (string, int, bool, choice, flag等)
            - required: 是否必需 (默认False)
            - description: 参数描述
            - choices: 可选值列表 (用于choice/flag类型)
            - default: 默认值
        timeout: 超时时间(秒)
        cache_result: 是否缓存结果
        cache_ttl: 缓存生存时间(秒)
        permission_required: 需要的权限
    """

    def decorator(func):
        metadata = FunctionMetadata(
            name=name,
            description=description,
            usage=usage or f"gs-{{plugin}}-{{subplugin}}-{name}",
            examples=examples or [],
            args=args or [],
            async_func=asyncio.iscoroutinefunction(func),
            timeout=timeout,
            cache_result=cache_result,
            cache_ttl=cache_ttl,
            permission_required=permission_required,
        )

        func._function_info = metadata
        func._is_plugin_function = True
        return func

    return decorator


def subplugin(name: str, description: str = "", version: str = "1.0.0"):
    """
    子插件类装饰器

    Args:
        name: 子插件名称
        description: 子插件描述
        version: 子插件版本
    """

    def decorator(cls):
        cls._subplugin_name = name
        cls._subplugin_description = description
        cls._subplugin_version = version
        cls._is_subplugin_class = True
        return cls

    return decorator


def plugin(name: str, description: str = "", version: str = "1.0.0", author: str = ""):
    """
    插件类装饰器

    Args:
        name: 插件名称
        description: 插件描述
        version: 插件版本
        author: 插件作者
    """

    def decorator(cls):
        cls._plugin_name = name
        cls._plugin_description = description
        cls._plugin_version = version
        cls._plugin_author = author
        cls._is_plugin_class = True
        return cls

    return decorator


def validate_args(
    min_args: int = None, max_args: int = None, required_devices: bool = False
):
    """
    参数验证装饰器

    Args:
        min_args: 最少参数个数
        max_args: 最多参数个数
        required_devices: 是否需要设备连接
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, args: List[str] = None):
            args = args or []

            # 参数数量验证
            if min_args is not None and len(args) < min_args:
                from gscripts.models.result import CommandResult

                return CommandResult(
                    success=False,
                    message=f"参数不足，至少需要 {min_args} 个参数",
                    exit_code=1,
                )

            if max_args is not None and len(args) > max_args:
                from gscripts.models.result import CommandResult

                return CommandResult(
                    success=False,
                    message=f"参数过多，最多接受 {max_args} 个参数",
                    exit_code=1,
                )

            # 设备连接验证
            if required_devices and hasattr(self, "check_device_connection"):
                device_check = await self.check_device_connection()
                if not device_check.success:
                    return device_check

            # 执行原函数
            return await func(self, args)

        # 保留原有的元数据
        if hasattr(func, "_function_info"):
            func._function_info.min_args = min_args
            func._function_info.max_args = max_args
            func._function_info.required_devices = required_devices
            wrapper._function_info = func._function_info
            wrapper._is_plugin_function = True

        return wrapper

    return decorator


def timing(log_execution_time: bool = True):
    """
    执行时间统计装饰器

    Args:
        log_execution_time: 是否在结果中记录执行时间
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            result = await func(*args, **kwargs)
            execution_time = time.time() - start_time

            if log_execution_time and hasattr(result, "execution_time"):
                result.execution_time = execution_time

            return result

        return wrapper

    return decorator


def cache_result(ttl: int = 300, key_func: Callable = None):
    """
    结果缓存装饰器

    Args:
        ttl: 缓存生存时间(秒)
        key_func: 自定义缓存键生成函数
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            # 生成缓存键
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                cache_key = (
                    f"{func.__module__}.{func.__name__}:{hash(str(args) + str(kwargs))}"
                )

            # 检查缓存
            current_time = time.time()
            if cache_key in _function_cache:
                cached_data = _function_cache[cache_key]
                if current_time - cached_data["timestamp"] < ttl:
                    return cached_data["result"]
                else:
                    # 缓存过期，删除
                    del _function_cache[cache_key]

            # 执行函数并缓存结果
            result = await func(*args, **kwargs)
            _function_cache[cache_key] = {"result": result, "timestamp": current_time}

            return result

        return wrapper

    return decorator


def permission_required(permission: str):
    """
    权限检查装饰器

    Args:
        permission: 需要的权限名称
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(self, *args, **kwargs):
            # 这里可以添加权限检查逻辑
            # 目前简单实现，实际项目中需要与权限系统集成
            if hasattr(self, "check_permission"):
                if not await self.check_permission(permission):
                    from gscripts.models.result import CommandResult

                    return CommandResult(
                        success=False,
                        message=f"权限不足，需要权限: {permission}",
                        exit_code=403,
                    )

            return await func(self, *args, **kwargs)

        # 保留权限信息
        if hasattr(func, "_function_info"):
            func._function_info.permission_required = permission
            wrapper._function_info = func._function_info
            wrapper._is_plugin_function = True

        return wrapper

    return decorator


def catch_exceptions(default_error_message: str = None, reraise: bool = False):
    """
    异常捕获装饰器

    Args:
        default_error_message: 默认错误信息
        reraise: 是否重新抛出异常
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                from gscripts.models.result import CommandResult

                error_msg = (
                    default_error_message
                    or f"执行 {func.__name__} 时发生错误: {str(e)}"
                )

                if reraise:
                    raise

                return CommandResult(success=False, message=error_msg, exit_code=1)

        return wrapper

    return decorator


def retry(max_attempts: int = 3, delay: float = 1.0, exponential_backoff: bool = False):
    """
    重试装饰器

    Args:
        max_attempts: 最大重试次数
        delay: 重试间隔(秒)
        exponential_backoff: 是否使用指数退避
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            last_exception = None

            for attempt in range(max_attempts):
                try:
                    result = await func(*args, **kwargs)
                    if hasattr(result, "success") and result.success:
                        return result
                    elif attempt == max_attempts - 1:
                        return result
                except Exception as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        break

                if attempt < max_attempts - 1:
                    wait_time = delay
                    if exponential_backoff:
                        wait_time = delay * (2**attempt)
                    await asyncio.sleep(wait_time)

            from gscripts.models.result import CommandResult

            error_msg = f"重试 {max_attempts} 次后仍然失败"
            if last_exception:
                error_msg += f": {str(last_exception)}"

            return CommandResult(success=False, message=error_msg, exit_code=1)

        return wrapper

    return decorator


def format_output(formatter: Callable = None, table_format: bool = False):
    """
    输出格式化装饰器

    Args:
        formatter: 自定义格式化函数
        table_format: 是否使用表格格式
    """

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            result = await func(*args, **kwargs)

            if formatter and hasattr(result, "stdout") and result.stdout:
                result.stdout = formatter(result.stdout)
            elif table_format and hasattr(result, "stdout") and result.stdout:
                # 简单的表格格式化
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    # 假设第一行是标题
                    headers = lines[0].split()
                    formatted_output = f"| {' | '.join(headers)} |\n"
                    formatted_output += f"|{'|'.join(['---'] * len(headers))}|\n"

                    for line in lines[1:]:
                        cells = line.split()
                        if len(cells) == len(headers):
                            formatted_output += f"| {' | '.join(cells)} |\n"

                    result.stdout = formatted_output

            return result

        return wrapper

    return decorator


def rate_limit(calls_per_second: float = 1.0):
    """
    速率限制装饰器

    Args:
        calls_per_second: 每秒允许的调用次数
    """
    last_called = {}
    min_interval = 1.0 / calls_per_second

    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            func_key = f"{func.__module__}.{func.__name__}"
            current_time = time.time()

            if func_key in last_called:
                time_since_last_call = current_time - last_called[func_key]
                if time_since_last_call < min_interval:
                    sleep_time = min_interval - time_since_last_call
                    await asyncio.sleep(sleep_time)

            last_called[func_key] = time.time()
            return await func(*args, **kwargs)

        return wrapper

    return decorator


# 便捷装饰器组合
def standard_plugin_function(
    name: str,
    description: str = "",
    min_args: int = None,
    max_args: int = None,
    required_devices: bool = False,
    examples: List[str] = None,
    cache_result: bool = False,
    cache_ttl: int = 300,
    permission_required: str = None,
    retry_attempts: int = 1,
):
    """
    标准插件函数装饰器组合
    """

    def decorator(func):
        func = plugin_function(
            name=name,
            description=description,
            examples=examples,
            cache_result=cache_result,
            cache_ttl=cache_ttl,
            permission_required=permission_required,
        )(func)
        func = validate_args(min_args, max_args, required_devices)(func)
        func = timing()(func)
        if cache_result:
            func = cache_result(ttl=cache_ttl)(func)
        if retry_attempts > 1:
            func = retry(max_attempts=retry_attempts)(func)
        func = catch_exceptions()(func)
        return func

    return decorator
