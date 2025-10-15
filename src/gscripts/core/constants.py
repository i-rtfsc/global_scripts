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
        if name.startswith('_') or name in ('mro', 'validate_command_safety', 'get_plugin_schema_path', 'get_i18n_file_path'):
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
    def PROJECT_NAME(self) -> str:
        return self._system_config.project.name

    @property
    def PROJECT_VERSION(self) -> str:
        return self._system_config.project.version

    @property
    def DEFAULT_AUTHOR(self) -> str:
        return self._system_config.project.default_author

    # ============= 目录路径常量 =============
    @property
    def GS_HOME(self) -> Path:
        return self.HOME_DIR / self._system_config.paths.gs_home

    @property
    def GS_CONFIG_DIR(self) -> Path:
        return self.GS_HOME / self._system_config.paths.config_dir

    @property
    def GS_PLUGINS_DIR(self) -> Path:
        return self.CURRENT_DIR  # 当前插件工程的根目录

    @property
    def GS_CACHE_DIR(self) -> Path:
        return self.GS_HOME / self._system_config.paths.cache_dir

    @property
    def GS_LOGS_DIR(self) -> Path:
        return self.GS_HOME / self._system_config.paths.logs_dir

    @property
    def GS_TEMP_DIR(self) -> Path:
        return self.GS_HOME / self._system_config.paths.temp_dir

    @property
    def GS_LOG_FILE(self) -> Path:
        return self.GS_LOGS_DIR / self._system_config.files.log_file

    @property
    def MAX_LOG_FILE_SIZE(self) -> int:
        return self._system_config.logging.max_file_size

    @property
    def PROJECT_CONFIG_DIR(self) -> Path:
        return self.CURRENT_DIR / self._system_config.paths.config_dir

    @property
    def PROJECT_I18N_FILE(self) -> Path:
        return self.PROJECT_CONFIG_DIR / self._system_config.files.i18n_config

    @property
    def PROJECT_MAIN_CONFIG(self) -> Path:
        return self.PROJECT_CONFIG_DIR / self._system_config.files.main_config

    # ============= 文件和目录名称 =============
    @property
    def DEFAULT_CONFIG_DIR(self) -> str:
        return self._system_config.paths.config_dir

    @property
    def DEFAULT_PLUGINS_DIR(self) -> str:
        return self._system_config.paths.plugins_dir

    @property
    def DEFAULT_TEMPLATES_DIR(self) -> str:
        return self._system_config.paths.templates_dir

    @property
    def DEFAULT_CACHE_DIR(self) -> str:
        return self._system_config.paths.cache_dir

    @property
    def DEFAULT_LOG_DIR(self) -> str:
        return self._system_config.paths.logs_dir

    # ============= 配置文件名 =============
    @property
    def MAIN_CONFIG_FILE(self) -> str:
        return self._system_config.files.main_config

    @property
    def I18N_CONFIG_FILE(self) -> str:
        return self._system_config.files.i18n_config

    @property
    def PLUGIN_SCHEMA_FILE(self) -> str:
        return self._system_config.files.plugin_schema

    @property
    def PLUGIN_TEMPLATE_FILE(self) -> str:
        return self._system_config.files.plugin_template

    @property
    def PLUGIN_JSON_FILE(self) -> str:
        return self._system_config.files.plugin_json

    @property
    def PLUGIN_PY_FILE(self) -> str:
        return self._system_config.files.plugin_py

    @property
    def PLUGIN_SH_FILE(self) -> str:
        return self._system_config.files.plugin_sh

    # ============= 插件相关 =============
    @property
    def PLUGIN_TYPES(self) -> Dict[str, str]:
        return self._system_config.plugins.supported_types

    # ============= 命令执行相关 =============
    @property
    def DEFAULT_TIMEOUT(self) -> int:
        return self._system_config.execution.timeouts.default

    @property
    def LONG_TIMEOUT(self) -> int:
        return self._system_config.execution.timeouts.long

    @property
    def SHORT_TIMEOUT(self) -> int:
        return self._system_config.execution.timeouts.short

    @property
    def MAX_OUTPUT_SIZE(self) -> int:
        return self._system_config.execution.limits.max_output_size

    @property
    def MAX_CONCURRENT_COMMANDS(self) -> int:
        return self._system_config.execution.limits.max_concurrent

    # ============= 安全命令列表 =============
    @property
    def SAFE_COMMANDS(self) -> List[str]:
        return self._system_config.execution.safe_commands.get_all()

    @property
    def DANGEROUS_COMMANDS(self) -> List[str]:
        return self._system_config.execution.dangerous_commands

    # ============= 语言相关 =============
    @property
    def DEFAULT_LANGUAGE(self) -> str:
        return self._system_config.language.default

    @property
    def SUPPORTED_LANGUAGES(self) -> List[str]:
        return self._system_config.language.supported

    # ============= 系统命令 =============
    @property
    def SYSTEM_COMMANDS(self) -> Dict[str, List[str]]:
        return {
            'help': self._system_config.commands.system.help.aliases,
            'version': self._system_config.commands.system.version.aliases,
            'plugin': self._system_config.commands.system.plugin.aliases,
            'status': self._system_config.commands.system.status.aliases,
            'update': self._system_config.commands.system.update.aliases,
            'refresh': self._system_config.commands.system.refresh.aliases,
            'doctor': self._system_config.commands.system.doctor.aliases
        }

    @property
    def PLUGIN_COMMANDS(self) -> Dict[str, List[str]]:
        return {
            'list': self._system_config.commands.plugin_management.list.aliases,
            'info': self._system_config.commands.plugin_management.info.aliases,
            'enable': self._system_config.commands.plugin_management.enable.aliases,
            'disable': self._system_config.commands.plugin_management.disable.aliases,
            'reload': self._system_config.commands.plugin_management.reload.aliases,
            'install': self._system_config.commands.plugin_management.install.aliases,
            'uninstall': self._system_config.commands.plugin_management.uninstall.aliases,
            'create': self._system_config.commands.plugin_management.create.aliases
        }

    # ============= 缓存相关 =============
    @property
    def DEFAULT_CACHE_TTL(self) -> int:
        return self._system_config.cache.default_ttl

    @property
    def MAX_CACHE_SIZE(self) -> int:
        return self._system_config.cache.max_entries

    # ============= 安全相关 =============
    @property
    def MAX_COMMAND_LENGTH(self) -> int:
        return self._system_config.execution.limits.max_command_length

    @property
    def FORBIDDEN_PATTERNS(self) -> List[str]:
        return self._system_config.execution.forbidden_patterns

    # ============= 状态常量 =============
    @property
    def STATUS_ENABLED(self) -> str:
        return self._system_config.status.enabled

    @property
    def STATUS_DISABLED(self) -> str:
        return self._system_config.status.disabled

    @property
    def STATUS_ERROR(self) -> str:
        return self._system_config.status.error

    @property
    def STATUS_LOADING(self) -> str:
        return self._system_config.status.loading

    # ============= 退出码 =============
    @property
    def EXIT_SUCCESS(self) -> int:
        return self._system_config.exit_codes.success

    @property
    def EXIT_GENERAL_ERROR(self) -> int:
        return self._system_config.exit_codes.general_error

    @property
    def EXIT_MISUSE(self) -> int:
        return self._system_config.exit_codes.misuse

    @property
    def EXIT_EXECUTION_ERROR(self) -> int:
        return self._system_config.exit_codes.execution_error

    @property
    def EXIT_COMMAND_NOT_FOUND(self) -> int:
        return self._system_config.exit_codes.command_not_found

    @property
    def EXIT_TIMEOUT(self) -> int:
        return self._system_config.exit_codes.timeout

    @property
    def EXIT_INTERRUPTED(self) -> int:
        return self._system_config.exit_codes.interrupted

    @property
    def EXIT_SECURITY_VIOLATION(self) -> int:
        return self._system_config.exit_codes.security_violation

    # ============= 日志级别 =============
    @property
    def LOG_LEVELS(self) -> Dict[str, int]:
        return self._system_config.logging.levels

    @property
    def LOG_LEVEL_ALIAS(self) -> Dict[str, str]:
        return self._system_config.logging.level_aliases

    # ============= 插件优先级 =============
    @property
    def DEFAULT_PLUGIN_PRIORITY(self) -> int:
        return self._system_config.plugins.priority['default']

    @property
    def MIN_PLUGIN_PRIORITY(self) -> int:
        return self._system_config.plugins.priority['min']

    @property
    def MAX_PLUGIN_PRIORITY(self) -> int:
        return self._system_config.plugins.priority['max']

    # ============= 网络相关 =============
    @property
    def DEFAULT_REQUEST_TIMEOUT(self) -> int:
        return self._system_config.network.request_timeout

    @property
    def MAX_RETRY_ATTEMPTS(self) -> int:
        return self._system_config.network.max_retry_attempts

    # ============= 颜色输出相关 =============
    @property
    def COLORS(self) -> Dict[str, str]:
        colors = self._system_config.ui.colors
        return {
            'RED': colors.red,
            'GREEN': colors.green,
            'YELLOW': colors.yellow,
            'BLUE': colors.blue,
            'MAGENTA': colors.magenta,
            'CYAN': colors.cyan,
            'WHITE': colors.white,
            'RESET': colors.reset,
            'BOLD': colors.bold,
            'UNDERLINE': colors.underline
        }

    # ============= Shell相关 =============
    @property
    def ENV_SH_FILE_NAME(self) -> str:
        return self._system_config.files.env_sh

    @property
    def SHELL_RELOAD_ALIAS(self) -> str:
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
        from .logger import VERBOSE_LEVEL  # local import to avoid circular at module load

        raw = None
        if isinstance(cfg, dict):
            raw = cfg.get('logging_level')
        if raw:
            raw_upper = str(raw).upper().strip()
            mapped = self.LOG_LEVEL_ALIAS.get(raw_upper, raw_upper)
            if mapped == 'NONE':
                return 1000
            if mapped == 'VERBOSE':
                return VERBOSE_LEVEL
            if hasattr(_logging, mapped):
                return getattr(_logging, mapped)
        debug_flag = bool(cfg.get('config_debug')) if isinstance(cfg, dict) else False
        verbose_flag = bool(cfg.get('config_verbose')) if isinstance(cfg, dict) else False
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
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        user_config_dir = instance.GS_HOME / instance._system_config.paths.config_dir
        project_config_dir = instance.PROJECT_CONFIG_DIR

        # 检查用户配置目录下是否有配置文件
        user_config_file = user_config_dir / instance.MAIN_CONFIG_FILE
        if user_config_file.exists():
            return user_config_dir

        # 如果用户配置文件不存在，使用项目配置目录
        return project_config_dir

    @classmethod
    def get_plugins_dir(cls) -> Path:
        """获取插件目录路径 - 当前插件工程的根目录"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        return instance.GS_PLUGINS_DIR

    @classmethod
    def get_cache_dir(cls) -> Path:
        """获取缓存目录路径 - ~/.config/global-scripts/cache"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        return instance.GS_CACHE_DIR

    @classmethod
    def get_language(cls) -> str:
        """获取当前语言设置 - 从配置读取，默认为en"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        return os.environ.get('GS_LANGUAGE', instance.DEFAULT_LANGUAGE)

    @classmethod
    def is_debug_mode(cls) -> bool:
        """检查是否为调试模式"""
        return os.environ.get('GS_DEBUG', '').lower() in ['1', 'true', 'yes', 'on']

    @classmethod
    def get_main_config_path(cls) -> Path:
        """获取主配置文件路径"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        return cls.get_config_dir() / instance.MAIN_CONFIG_FILE

    @classmethod
    def get_i18n_config_path(cls) -> Path:
        """获取国际化配置文件路径 - 优先级：~/.config/global-scripts/config > 当前工程/config"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        user_i18n_file = instance.GS_HOME / instance._system_config.paths.config_dir / instance.I18N_CONFIG_FILE
        project_i18n_file = instance.PROJECT_CONFIG_DIR / instance.I18N_CONFIG_FILE

        # 检查用户配置目录下是否有i18n配置文件
        if user_i18n_file.exists():
            return user_i18n_file

        # 如果用户配置文件不存在，使用项目配置文件
        return project_i18n_file

    @classmethod
    def get_plugin_schema_path(cls) -> Path:
        """获取插件Schema文件路径"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        return instance.CURRENT_DIR / instance._system_config.paths.schemas_dir / instance.PLUGIN_SCHEMA_FILE

    @classmethod
    def validate_command_safety(cls, command: str) -> bool:
        """验证命令是否安全"""
        instance = cls() if not hasattr(cls, '_instance') else cls._instance
        if len(command) > instance.MAX_COMMAND_LENGTH:
            return False

        command_lower = command.lower()
        for pattern in instance.FORBIDDEN_PATTERNS:
            if pattern in command_lower:
                return False

        return True


# 导出常量实例供其他模块使用
CONSTANTS = GlobalConstants()
