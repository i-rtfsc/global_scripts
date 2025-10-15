"""
System Configuration Loader
负责加载和验证 system_config.yaml 配置文件
使用 Pydantic 进行数据验证
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field


@dataclass
class ProjectConfig:
    """项目基本信息"""
    name: str = "Global Scripts"
    version: str = "6.0.0"
    default_author: str = "Unknown"


@dataclass
class PathsConfig:
    """目录路径配置"""
    gs_home: str = ".config/global-scripts"
    config_dir: str = "config"
    cache_dir: str = "cache"
    logs_dir: str = "logs"
    temp_dir: str = "tmp"
    plugins_dir: str = "plugins"
    custom_dir: str = "custom"
    templates_dir: str = "templates"
    schemas_dir: str = "schemas"
    themes_dir: str = "themes"


@dataclass
class FilesConfig:
    """文件名配置"""
    main_config: str = "gs.json"
    i18n_config: str = "i18n.json"
    plugin_schema: str = "plugin-schema.json"
    plugin_template: str = "plugin.json.template"
    plugin_json: str = "plugin.json"
    plugin_py: str = "plugin.py"
    plugin_sh: str = "plugin.sh"
    env_sh: str = "env.sh"
    env_fish: str = "env.fish"
    log_file: str = "gs.log"
    router_index: str = "router.json"


@dataclass
class PluginsConfig:
    """插件配置"""
    supported_types: Dict[str, str] = field(default_factory=lambda: {
        'python': 'Python',
        'shell': 'Shell',
        'hybrid': 'Hybrid',
        'config': 'Config',
        'json': 'JSON'
    })
    priority: Dict[str, int] = field(default_factory=lambda: {
        'default': 10,
        'min': 1,
        'max': 100
    })


@dataclass
class TimeoutsConfig:
    """超时配置"""
    default: int = 30
    short: int = 10
    long: int = 300


@dataclass
class ExecutionLimitsConfig:
    """执行限制配置"""
    max_output_size: int = 1048576  # 1MB
    max_concurrent: int = 10
    max_command_length: int = 1000


@dataclass
class SafeCommandsConfig:
    """安全命令配置"""
    filesystem: List[str] = field(default_factory=list)
    system: List[str] = field(default_factory=list)
    network: List[str] = field(default_factory=list)
    vcs: List[str] = field(default_factory=list)
    development: List[str] = field(default_factory=list)
    containers: List[str] = field(default_factory=list)
    mobile: List[str] = field(default_factory=list)
    compression: List[str] = field(default_factory=list)

    def get_all(self) -> List[str]:
        """获取所有安全命令的扁平列表"""
        return (
            self.filesystem +
            self.system +
            self.network +
            self.vcs +
            self.development +
            self.containers +
            self.mobile +
            self.compression
        )


@dataclass
class ExecutionConfig:
    """命令执行配置"""
    timeouts: TimeoutsConfig = field(default_factory=TimeoutsConfig)
    limits: ExecutionLimitsConfig = field(default_factory=ExecutionLimitsConfig)
    safe_commands: SafeCommandsConfig = field(default_factory=SafeCommandsConfig)
    dangerous_commands: List[str] = field(default_factory=list)
    forbidden_patterns: List[str] = field(default_factory=list)


@dataclass
class LanguageConfig:
    """语言配置"""
    default: str = "en"
    supported: List[str] = field(default_factory=lambda: ["en", "zh"])


@dataclass
class CommandAliasConfig:
    """命令别名配置"""
    aliases: List[str] = field(default_factory=list)


@dataclass
class SystemCommandsConfig:
    """系统命令配置"""
    help: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    version: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    plugin: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    status: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    update: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    refresh: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    doctor: CommandAliasConfig = field(default_factory=CommandAliasConfig)


@dataclass
class PluginManagementCommandsConfig:
    """插件管理命令配置"""
    list: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    info: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    enable: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    disable: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    reload: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    install: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    uninstall: CommandAliasConfig = field(default_factory=CommandAliasConfig)
    create: CommandAliasConfig = field(default_factory=CommandAliasConfig)


@dataclass
class CommandsConfig:
    """命令配置"""
    system: SystemCommandsConfig = field(default_factory=SystemCommandsConfig)
    plugin_management: PluginManagementCommandsConfig = field(default_factory=PluginManagementCommandsConfig)


@dataclass
class CacheConfig:
    """缓存配置"""
    default_ttl: int = 300
    max_entries: int = 100
    max_file_age: int = 3600


@dataclass
class LoggingConfig:
    """日志配置"""
    levels: Dict[str, int] = field(default_factory=lambda: {
        'DEBUG': 10,
        'INFO': 20,
        'WARNING': 30,
        'ERROR': 40,
        'CRITICAL': 50,
        'VERBOSE': 15,
        'NONE': 1000
    })
    level_aliases: Dict[str, str] = field(default_factory=lambda: {
        'E': 'ERROR',
        'W': 'WARNING',
        'I': 'INFO',
        'D': 'DEBUG',
        'V': 'VERBOSE',
        'NANO': 'NONE'
    })
    max_file_size: int = 10485760  # 10MB
    backup_count: int = 3
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format: str = "%Y-%m-%d %H:%M:%S"


@dataclass
class ExitCodesConfig:
    """退出码配置"""
    success: int = 0
    general_error: int = 1
    misuse: int = 2
    execution_error: int = 126
    command_not_found: int = 127
    timeout: int = 124
    interrupted: int = 130
    security_violation: int = 125


@dataclass
class StatusConfig:
    """状态常量配置"""
    enabled: str = "enabled"
    disabled: str = "disabled"
    error: str = "error"
    loading: str = "loading"
    unknown: str = "unknown"


@dataclass
class ColorsConfig:
    """颜色配置"""
    red: str = '\033[91m'
    green: str = '\033[92m'
    yellow: str = '\033[93m'
    blue: str = '\033[94m'
    magenta: str = '\033[95m'
    cyan: str = '\033[96m'
    white: str = '\033[97m'
    reset: str = '\033[0m'
    bold: str = '\033[1m'
    underline: str = '\033[4m'


@dataclass
class IconsConfig:
    """图标配置"""
    success: str = "✅"
    error: str = "❌"
    warning: str = "⚠️"
    info: str = "ℹ️"
    folder: str = "📁"
    file: str = "📄"
    plugin: str = "🔌"
    command: str = "⚡"
    loading: str = "⏳"


@dataclass
class UIConfig:
    """UI配置"""
    colors: ColorsConfig = field(default_factory=ColorsConfig)
    icons: IconsConfig = field(default_factory=IconsConfig)


@dataclass
class NetworkConfig:
    """网络配置"""
    request_timeout: int = 30
    max_retry_attempts: int = 3
    retry_delay: int = 1
    user_agent: str = "Global-Scripts/6.0.0"


@dataclass
class ShellConfig:
    """Shell配置"""
    reload_alias: str = "gsreload"
    supported_shells: List[str] = field(default_factory=lambda: ["bash", "zsh", "fish"])
    prompt_themes: List[str] = field(default_factory=lambda: ["minimalist", "bitstream", "powerline", "simple"])


@dataclass
class SecurityConfig:
    """安全配置"""
    enable_sandbox: bool = True
    allow_network_access: bool = True
    max_subprocess_depth: int = 3
    require_confirmation_for_destructive: bool = True
    confirmation_required: List[str] = field(default_factory=lambda: ["sudo", "rm", "format", "dd"])


@dataclass
class FeaturesConfig:
    """特性开关配置"""
    enable_auto_update: bool = False
    enable_telemetry: bool = False
    enable_plugin_marketplace: bool = False
    enable_command_history: bool = True
    enable_completion_cache: bool = True
    show_examples: bool = True
    show_tips: bool = True


@dataclass
class PerformanceConfig:
    """性能配置"""
    lazy_load_plugins: bool = True
    cache_plugin_metadata: bool = True
    parallel_plugin_load: bool = True
    max_parallel_loaders: int = 4
    startup_timeout: int = 10


@dataclass
class SystemConfig:
    """系统配置总容器"""
    project: ProjectConfig = field(default_factory=ProjectConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    files: FilesConfig = field(default_factory=FilesConfig)
    plugins: PluginsConfig = field(default_factory=PluginsConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    language: LanguageConfig = field(default_factory=LanguageConfig)
    commands: CommandsConfig = field(default_factory=CommandsConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    exit_codes: ExitCodesConfig = field(default_factory=ExitCodesConfig)
    status: StatusConfig = field(default_factory=StatusConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    shell: ShellConfig = field(default_factory=ShellConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    features: FeaturesConfig = field(default_factory=FeaturesConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)


class SystemConfigLoader:
    """系统配置加载器"""

    def __init__(self, config_path: Optional[Path] = None):
        """
        初始化配置加载器

        Args:
            config_path: 配置文件路径，默认为 config/system_config.yaml
        """
        if config_path is None:
            # 默认配置文件路径
            current_dir = Path(__file__).parent.parent.parent.parent
            config_path = current_dir / "config" / "system_config.yaml"

        self.config_path = config_path
        self._config: Optional[SystemConfig] = None

    def load(self) -> SystemConfig:
        """
        加载配置文件

        Returns:
            SystemConfig: 系统配置对象

        Raises:
            FileNotFoundError: 配置文件不存在
            yaml.YAMLError: YAML 解析错误
        """
        if self._config is not None:
            return self._config

        if not self.config_path.exists():
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

        with open(self.config_path, 'r', encoding='utf-8') as f:
            raw_config = yaml.safe_load(f)

        self._config = self._parse_config(raw_config)
        return self._config

    def _parse_config(self, raw: Dict[str, Any]) -> SystemConfig:
        """
        解析原始配置字典为配置对象

        Args:
            raw: 原始配置字典

        Returns:
            SystemConfig: 系统配置对象
        """
        config = SystemConfig()

        # 解析各个配置段
        if 'project' in raw:
            config.project = self._parse_project(raw['project'])

        if 'paths' in raw:
            config.paths = self._parse_paths(raw['paths'])

        if 'files' in raw:
            config.files = self._parse_files(raw['files'])

        if 'plugins' in raw:
            config.plugins = self._parse_plugins(raw['plugins'])

        if 'execution' in raw:
            config.execution = self._parse_execution(raw['execution'])

        if 'language' in raw:
            config.language = self._parse_language(raw['language'])

        if 'commands' in raw:
            config.commands = self._parse_commands(raw['commands'])

        if 'cache' in raw:
            config.cache = self._parse_cache(raw['cache'])

        if 'logging' in raw:
            config.logging = self._parse_logging(raw['logging'])

        if 'exit_codes' in raw:
            config.exit_codes = self._parse_exit_codes(raw['exit_codes'])

        if 'status' in raw:
            config.status = self._parse_status(raw['status'])

        if 'ui' in raw:
            config.ui = self._parse_ui(raw['ui'])

        if 'network' in raw:
            config.network = self._parse_network(raw['network'])

        if 'shell' in raw:
            config.shell = self._parse_shell(raw['shell'])

        if 'security' in raw:
            config.security = self._parse_security(raw['security'])

        if 'features' in raw:
            config.features = self._parse_features(raw['features'])

        if 'performance' in raw:
            config.performance = self._parse_performance(raw['performance'])

        return config

    def _parse_project(self, data: Dict) -> ProjectConfig:
        # 从 VERSION 文件读取版本号（优先于配置文件）
        version_file = self.config_path.parent.parent / "VERSION"
        if version_file.exists():
            try:
                version = version_file.read_text().strip()
                data = {**data, 'version': version}  # 覆盖配置文件中的版本
            except Exception:
                pass  # 如果读取失败，使用配置文件中的版本
        return ProjectConfig(**data)

    def _parse_paths(self, data: Dict) -> PathsConfig:
        return PathsConfig(**data)

    def _parse_files(self, data: Dict) -> FilesConfig:
        return FilesConfig(**data)

    def _parse_plugins(self, data: Dict) -> PluginsConfig:
        return PluginsConfig(**data)

    def _parse_execution(self, data: Dict) -> ExecutionConfig:
        config = ExecutionConfig()

        if 'timeouts' in data:
            config.timeouts = TimeoutsConfig(**data['timeouts'])

        if 'limits' in data:
            config.limits = ExecutionLimitsConfig(**data['limits'])

        if 'safe_commands' in data:
            safe_cmds = data['safe_commands']
            config.safe_commands = SafeCommandsConfig(
                filesystem=safe_cmds.get('filesystem', []),
                system=safe_cmds.get('system', []),
                network=safe_cmds.get('network', []),
                vcs=safe_cmds.get('vcs', []),
                development=safe_cmds.get('development', []),
                containers=safe_cmds.get('containers', []),
                mobile=safe_cmds.get('mobile', []),
                compression=safe_cmds.get('compression', [])
            )

        if 'dangerous_commands' in data:
            config.dangerous_commands = data['dangerous_commands']

        if 'forbidden_patterns' in data:
            config.forbidden_patterns = data['forbidden_patterns']

        return config

    def _parse_language(self, data: Dict) -> LanguageConfig:
        return LanguageConfig(**data)

    def _parse_commands(self, data: Dict) -> CommandsConfig:
        config = CommandsConfig()

        if 'system' in data:
            system_cmds = {}
            for key, value in data['system'].items():
                system_cmds[key] = CommandAliasConfig(**value)
            config.system = SystemCommandsConfig(**system_cmds)

        if 'plugin_management' in data:
            plugin_cmds = {}
            for key, value in data['plugin_management'].items():
                plugin_cmds[key] = CommandAliasConfig(**value)
            config.plugin_management = PluginManagementCommandsConfig(**plugin_cmds)

        return config

    def _parse_cache(self, data: Dict) -> CacheConfig:
        return CacheConfig(**data)

    def _parse_logging(self, data: Dict) -> LoggingConfig:
        return LoggingConfig(**data)

    def _parse_exit_codes(self, data: Dict) -> ExitCodesConfig:
        return ExitCodesConfig(**data)

    def _parse_status(self, data: Dict) -> StatusConfig:
        return StatusConfig(**data)

    def _parse_ui(self, data: Dict) -> UIConfig:
        config = UIConfig()

        if 'colors' in data:
            config.colors = ColorsConfig(**data['colors'])

        if 'icons' in data:
            config.icons = IconsConfig(**data['icons'])

        return config

    def _parse_network(self, data: Dict) -> NetworkConfig:
        return NetworkConfig(**data)

    def _parse_shell(self, data: Dict) -> ShellConfig:
        return ShellConfig(**data)

    def _parse_security(self, data: Dict) -> SecurityConfig:
        return SecurityConfig(**data)

    def _parse_features(self, data: Dict) -> FeaturesConfig:
        return FeaturesConfig(**data)

    def _parse_performance(self, data: Dict) -> PerformanceConfig:
        return PerformanceConfig(**data)

    def reload(self) -> SystemConfig:
        """
        重新加载配置

        Returns:
            SystemConfig: 系统配置对象
        """
        self._config = None
        return self.load()

    def get_config(self) -> SystemConfig:
        """
        获取配置对象（如果未加载则自动加载）

        Returns:
            SystemConfig: 系统配置对象
        """
        if self._config is None:
            return self.load()
        return self._config


# 全局配置加载器单例
_global_loader: Optional[SystemConfigLoader] = None


def get_system_config_loader() -> SystemConfigLoader:
    """
    获取全局系统配置加载器单例

    Returns:
        SystemConfigLoader: 配置加载器实例
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = SystemConfigLoader()
    return _global_loader


def get_system_config() -> SystemConfig:
    """
    获取系统配置（便捷函数）

    Returns:
        SystemConfig: 系统配置对象
    """
    return get_system_config_loader().get_config()
