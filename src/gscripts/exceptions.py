"""
Global Scripts 异常层次结构
Phase 6: 统一异常处理

提供清晰的异常分类，便于：
1. 精确捕获和处理特定错误
2. 统一错误码映射
3. 更好的错误信息展示
4. 简化错误处理逻辑
"""

from typing import Optional, Dict, Any


# ============= 基础异常类 =============

class GScriptsError(Exception):
    """
    Global Scripts 基础异常类

    所有自定义异常的基类
    """

    def __init__(
        self,
        message: str,
        exit_code: int = 1,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        初始化异常

        Args:
            message: 错误消息
            exit_code: 退出码
            details: 额外的错误详情
        """
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code
        self.details = details or {}

    def __str__(self) -> str:
        return self.message


# ============= 配置相关异常 =============

class ConfigError(GScriptsError):
    """配置错误基类"""

    def __init__(self, message: str, config_path: Optional[str] = None, **kwargs):
        super().__init__(message, exit_code=2, **kwargs)
        self.config_path = config_path


class ConfigNotFoundError(ConfigError):
    """配置文件未找到"""

    def __init__(self, config_path: str):
        super().__init__(
            f"Configuration file not found: {config_path}",
            config_path=config_path
        )


class ConfigValidationError(ConfigError):
    """配置验证失败"""

    def __init__(self, message: str, errors: list = None, **kwargs):
        super().__init__(message, **kwargs)
        self.validation_errors = errors or []


class ConfigParseError(ConfigError):
    """配置解析失败"""
    pass


# ============= 插件相关异常 =============

class PluginError(GScriptsError):
    """插件错误基类"""

    def __init__(self, message: str, plugin_name: Optional[str] = None, **kwargs):
        super().__init__(message, exit_code=3, **kwargs)
        self.plugin_name = plugin_name


class PluginNotFoundError(PluginError):
    """插件未找到"""

    def __init__(self, plugin_name: str):
        super().__init__(
            f"Plugin not found: {plugin_name}",
            plugin_name=plugin_name,
            exit_code=127  # Command not found
        )


class PluginLoadError(PluginError):
    """插件加载失败"""

    def __init__(self, plugin_name: str, reason: str, original_error: Optional[Exception] = None):
        super().__init__(
            f"Failed to load plugin '{plugin_name}': {reason}",
            plugin_name=plugin_name
        )
        self.reason = reason
        self.original_error = original_error


class PluginValidationError(PluginError):
    """插件验证失败"""

    def __init__(self, plugin_name: str, errors: list):
        message = f"Plugin validation failed for '{plugin_name}': {', '.join(errors)}"
        super().__init__(message, plugin_name=plugin_name)
        self.validation_errors = errors


class PluginDisabledError(PluginError):
    """插件已禁用"""

    def __init__(self, plugin_name: str):
        super().__init__(
            f"Plugin '{plugin_name}' is disabled",
            plugin_name=plugin_name
        )


class PluginDependencyError(PluginError):
    """插件依赖错误"""

    def __init__(self, plugin_name: str, missing_dependencies: list):
        deps = ', '.join(missing_dependencies)
        super().__init__(
            f"Plugin '{plugin_name}' has missing dependencies: {deps}",
            plugin_name=plugin_name
        )
        self.missing_dependencies = missing_dependencies


# ============= 函数/命令相关异常 =============

class FunctionError(GScriptsError):
    """函数错误基类"""

    def __init__(
        self,
        message: str,
        plugin_name: Optional[str] = None,
        function_name: Optional[str] = None,
        **kwargs
    ):
        super().__init__(message, exit_code=4, **kwargs)
        self.plugin_name = plugin_name
        self.function_name = function_name


class FunctionNotFoundError(FunctionError):
    """函数未找到"""

    def __init__(self, plugin_name: str, function_name: str):
        super().__init__(
            f"Function '{function_name}' not found in plugin '{plugin_name}'",
            plugin_name=plugin_name,
            function_name=function_name,
            exit_code=127
        )


class FunctionExecutionError(FunctionError):
    """函数执行失败"""

    def __init__(
        self,
        plugin_name: str,
        function_name: str,
        reason: str,
        original_error: Optional[Exception] = None
    ):
        super().__init__(
            f"Failed to execute {plugin_name}.{function_name}: {reason}",
            plugin_name=plugin_name,
            function_name=function_name
        )
        self.reason = reason
        self.original_error = original_error


class CommandNotFoundError(GScriptsError):
    """命令未找到"""

    def __init__(self, command: str):
        super().__init__(
            f"Command not found: {command}",
            exit_code=127
        )
        self.command = command


# ============= 执行相关异常 =============

class ExecutionError(GScriptsError):
    """执行错误基类"""

    def __init__(self, message: str, command: Optional[str] = None, **kwargs):
        super().__init__(message, exit_code=1, **kwargs)
        self.command = command


class CommandExecutionError(ExecutionError):
    """命令执行失败"""

    def __init__(self, command: str, return_code: int, stderr: str = ""):
        super().__init__(
            f"Command failed with exit code {return_code}: {command}",
            command=command,
            exit_code=return_code
        )
        self.return_code = return_code
        self.stderr = stderr


class TimeoutError(ExecutionError):
    """执行超时"""

    def __init__(self, command: str, timeout: int):
        super().__init__(
            f"Command timed out after {timeout}s: {command}",
            command=command,
            exit_code=124  # timeout command exit code
        )
        self.timeout = timeout


class SecurityViolationError(ExecutionError):
    """安全违规"""

    def __init__(self, command: str, reason: str):
        super().__init__(
            f"Security violation: {reason}",
            command=command,
            exit_code=125
        )
        self.reason = reason


# ============= 验证相关异常 =============

class ValidationError(GScriptsError):
    """验证错误基类"""

    def __init__(self, message: str, field: Optional[str] = None, **kwargs):
        super().__init__(message, exit_code=22, **kwargs)  # EINVAL
        self.field = field


class ArgumentError(ValidationError):
    """参数错误"""

    def __init__(self, message: str, argument: Optional[str] = None):
        super().__init__(message, field=argument)
        self.argument = argument


class PathError(ValidationError):
    """路径错误"""

    def __init__(self, message: str, path: Optional[str] = None):
        super().__init__(message, field=path)
        self.path = path


# ============= 系统相关异常 =============

class SystemError(GScriptsError):
    """系统错误基类"""

    def __init__(self, message: str, **kwargs):
        super().__init__(message, exit_code=1, **kwargs)


class InitializationError(SystemError):
    """初始化失败"""
    pass


class ResourceNotFoundError(SystemError):
    """资源未找到"""

    def __init__(self, resource_type: str, resource_name: str):
        super().__init__(
            f"{resource_type} not found: {resource_name}",
            exit_code=2
        )
        self.resource_type = resource_type
        self.resource_name = resource_name


class PermissionError(SystemError):
    """权限错误"""

    def __init__(self, message: str, path: Optional[str] = None):
        super().__init__(message, exit_code=13)  # EACCES
        self.path = path


# ============= 辅助函数 =============

def get_exit_code(error: Exception) -> int:
    """
    从异常获取退出码

    Args:
        error: 异常对象

    Returns:
        int: 退出码，默认为1
    """
    if isinstance(error, GScriptsError):
        return error.exit_code
    return 1


def format_error_message(error: Exception) -> str:
    """
    格式化错误消息

    Args:
        error: 异常对象

    Returns:
        str: 格式化的错误消息
    """
    if isinstance(error, GScriptsError):
        return error.message
    return str(error)


def is_retryable_error(error: Exception) -> bool:
    """
    判断错误是否可重试

    Args:
        error: 异常对象

    Returns:
        bool: 是否可重试
    """
    # 超时、网络错误等可重试
    if isinstance(error, TimeoutError):
        return True

    # 配置错误、验证错误等不可重试
    if isinstance(error, (ConfigError, ValidationError, SecurityViolationError)):
        return False

    # 默认不可重试
    return False
