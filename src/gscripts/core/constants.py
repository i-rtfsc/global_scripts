"""
全局常量定义
用于统一管理整个项目中使用的常量

重构说明：
- 从 system_config.yaml 加载配置，消除硬编码
- 保持向后兼容的 API
- 使用懒加载提高性能
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional
from functools import cached_property


class SingletonMeta(type):
    """单例元类，使类属性访问重定向到单例实例"""

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)
        return cls._instances[cls]

    def __getattribute__(cls, name):
        # 对于特殊属性和方法，使用默认行为
        if name.startswith("_") or name in (
            "mro",
            "validate_command_safety",
            "get_plugin_schema_path",
            "get_i18n_file_path",
        ):
            return super().__getattribute__(name)

        # 对于普通属性，尝试从单例实例获取
        try:
            instance = cls._instances.get(cls)
            if instance is None:
                instance = super().__call__()
            return getattr(instance, name)
        except (KeyError, AttributeError):
            return super().__getattribute__(name)


class GlobalConstants(metaclass=SingletonMeta):
    """
    全局常量类 - 重构版

    从 system_config.yaml 加载配置而非硬编码
    保持向后兼容性，现有代码无需修改
    """

    def __init__(self):
        """初始化常量类"""
        self._config: Optional[Any] = None  # SystemConfig 类型，延迟导入避免循环依赖

    @cached_property
    def _system_config(self):
        """懒加载系统配置"""
        # 延迟导入避免循环依赖
        from .system_config_loader import get_system_config

        return get_system_config()

    # ============= 基础目录常量（静态） =============
    HOME_DIR = Path.home()
    CURRENT_DIR = Path.cwd()

    # ============= 项目基础信息 =============
    @property
    def project_name(self) -> str:
        return self._system_config.project.name

    @property
    def project_version(self) -> str:
        return self._system_config.project.version

    @property
    def default_author(self) -> str:
        return self._system_config.project.default_author

    # ============= 目录路径常量 =============
    @property
    def gs_home(self) -> Path:
        return self.HOME_DIR / self._system_config.paths.gs_home

    @property
    def gs_config_dir(self) -> Path:
        return self.gs_home / self._system_config.paths.config_dir

    @property
    def gs_plugins_dir(self) -> Path:
        return self.CURRENT_DIR  # 当前插件工程的根目录

    @property
    def gs_cache_dir(self) -> Path:
        return self.gs_home / self._system_config.paths.cache_dir

    @property
    def gs_logs_dir(self) -> Path:
        return self.gs_home / self._system_config.paths.logs_dir

    @property
    def gs_temp_dir(self) -> Path:
        return self.gs_home / self._system_config.paths.temp_dir

    @property
    def gs_log_file(self) -> Path:
        return self.gs_logs_dir / self._system_config.files.log_file

    @property
    def max_log_file_size(self) -> int:
        return self._system_config.logging.max_file_size

    @property
    def project_config_dir(self) -> Path:
        return self.CURRENT_DIR / self._system_config.paths.config_dir

    @property
    def project_i18n_file(self) -> Path:
        return self.project_config_dir / self._system_config.files.i18n_config

    @property
    def project_main_config(self) -> Path:
        return self.project_config_dir / self._system_config.files.main_config

    # ============= 文件和目录名称 =============
    @property
    def default_config_dir(self) -> str:
        return self._system_config.paths.config_dir

    @property
    def default_plugins_dir(self) -> str:
        return self._system_config.paths.plugins_dir

    @property
    def default_templates_dir(self) -> str:
        return self._system_config.paths.templates_dir

    @property
    def default_cache_dir(self) -> str:
        return self._system_config.paths.cache_dir

    @property
    def default_log_dir(self) -> str:
        return self._system_config.paths.logs_dir

    # ============= 配置文件名 =============
    @property
    def main_config_file(self) -> str:
        return self._system_config.files.main_config

    @property
    def i18n_config_file(self) -> str:
        return self._system_config.files.i18n_config

    @property
    def plugin_schema_file(self) -> str:
        return self._system_config.files.plugin_schema

    @property
    def plugin_template_file(self) -> str:
        return self._system_config.files.plugin_template

    @property
    def plugin_json_file(self) -> str:
        return self._system_config.files.plugin_json

    @property
    def plugin_py_file(self) -> str:
        return self._system_config.files.plugin_py

    @property
    def plugin_sh_file(self) -> str:
        return self._system_config.files.plugin_sh

    # ============= 插件相关 =============
    @property
    def plugin_types(self) -> Dict[str, str]:
        return self._system_config.plugins.supported_types

    # ============= 命令执行相关 =============
    @property
    def default_timeout(self) -> int:
        return self._system_config.execution.timeouts.default

    @property
    def long_timeout(self) -> int:
        return self._system_config.execution.timeouts.long

    @property
    def short_timeout(self) -> int:
        return self._system_config.execution.timeouts.short

    @property
    def max_output_size(self) -> int:
        return self._system_config.execution.limits.max_output_size

    @property
    def max_concurrent_commands(self) -> int:
        return self._system_config.execution.limits.max_concurrent

    # ============= 安全命令列表 =============
    @property
    def safe_commands(self) -> List[str]:
        return self._system_config.execution.safe_commands.get_all()

    @property
    def dangerous_commands(self) -> List[str]:
        return self._system_config.execution.dangerous_commands

    # ============= 语言相关 =============
    @property
    def default_language(self) -> str:
        return self._system_config.language.default

    @property
    def supported_languages(self) -> List[str]:
        return self._system_config.language.supported

    # ============= 缓存相关 =============
    @property
    def default_cache_ttl(self) -> int:
        return self._system_config.cache.default_ttl

    @property
    def max_cache_size(self) -> int:
        return self._system_config.cache.max_entries

    # ============= 安全相关 =============
    @property
    def max_command_length(self) -> int:
        return self._system_config.execution.limits.max_command_length

    @property
    def forbidden_patterns(self) -> List[str]:
        return self._system_config.execution.forbidden_patterns

    # ============= 状态常量 =============
    @property
    def status_enabled(self) -> str:
        return self._system_config.status.enabled

    @property
    def status_disabled(self) -> str:
        return self._system_config.status.disabled

    @property
    def status_error(self) -> str:
        return self._system_config.status.error

    @property
    def status_loading(self) -> str:
        return self._system_config.status.loading

    # ============= 退出码 =============
    @property
    def exit_success(self) -> int:
        return self._system_config.exit_codes.success

    @property
    def exit_general_error(self) -> int:
        return self._system_config.exit_codes.general_error

    @property
    def exit_misuse(self) -> int:
        return self._system_config.exit_codes.misuse

    @property
    def exit_invalid_arguments(self) -> int:
        return self._system_config.exit_codes.invalid_arguments

    @property
    def exit_execution_error(self) -> int:
        return self._system_config.exit_codes.execution_error

    @property
    def exit_command_not_found(self) -> int:
        return self._system_config.exit_codes.command_not_found

    @property
    def exit_plugin_not_found(self) -> int:
        return self._system_config.exit_codes.plugin_not_found

    @property
    def exit_timeout(self) -> int:
        return self._system_config.exit_codes.timeout

    @property
    def exit_interrupted(self) -> int:
        return self._system_config.exit_codes.interrupted

    @property
    def exit_security_violation(self) -> int:
        return self._system_config.exit_codes.security_violation

    # ============= 日志级别 =============
    @property
    def log_levels(self) -> Dict[str, int]:
        return self._system_config.logging.levels

    @property
    def log_level_alias(self) -> Dict[str, str]:
        return self._system_config.logging.level_aliases

    # ============= 插件优先级 =============
    @property
    def default_plugin_priority(self) -> int:
        return self._system_config.plugins.priority["default"]

    @property
    def min_plugin_priority(self) -> int:
        return self._system_config.plugins.priority["min"]

    @property
    def max_plugin_priority(self) -> int:
        return self._system_config.plugins.priority["max"]

    # ============= 网络相关 =============
    @property
    def default_request_timeout(self) -> int:
        return self._system_config.network.request_timeout

    @property
    def max_retry_attempts(self) -> int:
        return self._system_config.network.max_retry_attempts

    # ============= 颜色输出相关 =============
    @property
    def colors(self) -> Dict[str, str]:
        colors = self._system_config.ui.colors
        return {
            "RED": colors.red,
            "GREEN": colors.green,
            "YELLOW": colors.yellow,
            "BLUE": colors.blue,
            "MAGENTA": colors.magenta,
            "CYAN": colors.cyan,
            "WHITE": colors.white,
            "RESET": colors.reset,
            "BOLD": colors.bold,
            "UNDERLINE": colors.underline,
        }

    # ============= Shell相关 =============
    @property
    def env_sh_file_name(self) -> str:
        return self._system_config.files.env_sh

    @property
    def shell_reload_alias(self) -> str:
        return self._system_config.shell.reload_alias

    # ============= 类方法（保持向后兼容） =============
    def resolve_logging_level(self, cfg: dict) -> int:
        """Resolve effective logging level from config dict.

        Priority (new unified model):
          1. cfg['logging_level'] (accept short E/W/I/D/V/NANO or full names)
          2. Legacy flags config_debug/config_verbose (DEPRECATED) -> mapped to DEBUG / VERBOSE
          3. Environment GS_DEBUG -> DEBUG when truthy
          4. Default -> INFO

        Special values:
          NANO => disable logging entirely (numeric 1000)
          VERBOSE (or alias V) => custom level between DEBUG(10) and INFO(20) defined as VERBOSE_LEVEL (15)

        Backwards compatibility:
          Legacy keys are still honored here but are stripped from in-memory config by ConfigManager
        """
        import logging as _logging
        from .logger import (
            VERBOSE_LEVEL,
        )  # local import to avoid circular at module load

        raw = None
        if isinstance(cfg, dict):
            raw = cfg.get("logging_level")
        if raw:
            raw_upper = str(raw).upper().strip()
            mapped = self.log_level_alias.get(raw_upper, raw_upper)
            if mapped == "NONE":
                return 1000
            if mapped == "VERBOSE":
                return VERBOSE_LEVEL
            if hasattr(_logging, mapped):
                return getattr(_logging, mapped)
        debug_flag = bool(cfg.get("config_debug")) if isinstance(cfg, dict) else False
        verbose_flag = (
            bool(cfg.get("config_verbose")) if isinstance(cfg, dict) else False
        )
        if debug_flag:
            return _logging.DEBUG
        if verbose_flag:
            try:
                from .logger import VERBOSE_LEVEL as _V

                return _V
            except Exception:
                return _logging.INFO
        if self.is_debug_mode():
            return _logging.DEBUG
        return _logging.INFO

    @classmethod
    def get_config_dir(cls) -> Path:
        """获取配置目录路径 - 优先级：~/.config/global-scripts/config > 当前工程/config"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        user_config_dir = instance.gs_home / instance._system_config.paths.config_dir
        project_config_dir = instance.project_config_dir

        # 检查用户配置目录下是否有配置文件
        user_config_file = user_config_dir / instance.main_config_file
        if user_config_file.exists():
            return user_config_dir

        # 如果用户配置文件不存在，使用项目配置目录
        return project_config_dir

    @classmethod
    def get_plugins_dir(cls) -> Path:
        """获取插件目录路径 - 当前插件工程的根目录"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        return instance.gs_plugins_dir

    @classmethod
    def get_cache_dir(cls) -> Path:
        """获取缓存目录路径 - ~/.config/global-scripts/cache"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        return instance.gs_cache_dir

    @classmethod
    def get_language(cls) -> str:
        """获取当前语言设置 - 从配置读取，默认为en"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        return os.environ.get("GS_LANGUAGE", instance.default_language)

    @classmethod
    def is_debug_mode(cls) -> bool:
        """检查是否为调试模式"""
        return os.environ.get("GS_DEBUG", "").lower() in ["1", "true", "yes", "on"]

    @classmethod
    def get_main_config_path(cls) -> Path:
        """获取主配置文件路径"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        return cls.get_config_dir() / instance.main_config_file

    @classmethod
    def get_i18n_config_path(cls) -> Path:
        """获取国际化配置文件路径 - 优先级：~/.config/global-scripts/config > 当前工程/config"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        user_i18n_file = (
            instance.gs_home
            / instance._system_config.paths.config_dir
            / instance.i18n_config_file
        )
        project_i18n_file = instance.project_config_dir / instance.i18n_config_file

        # 检查用户配置目录下是否有i18n配置文件
        if user_i18n_file.exists():
            return user_i18n_file

        # 如果用户配置文件不存在，使用项目配置文件
        return project_i18n_file

    @classmethod
    def get_plugin_schema_path(cls) -> Path:
        """获取插件Schema文件路径"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        return (
            instance.CURRENT_DIR
            / instance._system_config.paths.schemas_dir
            / instance.plugin_schema_file
        )

    @classmethod
    def validate_command_safety(cls, command: str) -> bool:
        """验证命令是否安全"""
        instance = cls() if not hasattr(cls, "_instance") else cls._instance
        if len(command) > instance.max_command_length:
            return False

        command_lower = command.lower()
        for pattern in instance.forbidden_patterns:
            if pattern in command_lower:
                return False

        return True


# 导出常量实例供其他模块使用
CONSTANTS = GlobalConstants()
