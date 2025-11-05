"""
Command pattern base classes
命令模式基类 - 定义统一的命令接口
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Optional, Any

from gscripts.models.result import CommandResult
from gscripts.core.config_manager import ConfigManager
from gscripts.application.services import PluginService, PluginExecutor
from ...core.constants import GlobalConstants
from ...utils.i18n import I18nManager
from ..formatters import OutputFormatter


class Command(ABC):
    """命令接口 - 所有命令的基类"""

    def __init__(
        self,
        config_manager: ConfigManager,
        plugin_service: PluginService,
        plugin_executor: PluginExecutor,
        i18n: I18nManager,
        formatter: OutputFormatter,
        constants: GlobalConstants,
        chinese: bool = True,
    ):
        self.config_manager = config_manager
        self.plugin_service = plugin_service
        self.plugin_executor = plugin_executor
        self.i18n = i18n
        self.formatter = formatter
        self.constants = constants
        self.chinese = chinese

    @abstractmethod
    async def execute(self, args: List[str]) -> CommandResult:
        """
        执行命令

        Args:
            args: 命令参数（不包含命令名本身）

        Returns:
            CommandResult: 执行结果
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """命令名称"""
        pass

    @property
    def aliases(self) -> List[str]:
        """命令别名"""
        return []

    @property
    def help_text(self) -> str:
        """帮助文本"""
        return ""


class CommandRegistry:
    """命令注册表 - 管理所有可用命令"""

    def __init__(self):
        self._commands: Dict[str, Command] = {}
        self._aliases: Dict[str, str] = {}  # alias -> command_name

    def register(self, command: Command) -> None:
        """
        注册命令

        Args:
            command: 命令实例
        """
        # 注册主命令名
        self._commands[command.name] = command

        # 注册别名
        for alias in command.aliases:
            self._aliases[alias] = command.name

    def register_multiple(self, commands: List[Command]) -> None:
        """批量注册命令"""
        for command in commands:
            self.register(command)

    def get(self, name: str) -> Optional[Command]:
        """
        获取命令

        Args:
            name: 命令名或别名

        Returns:
            Command: 命令实例，不存在返回 None
        """
        # 先检查是否是别名
        if name in self._aliases:
            name = self._aliases[name]

        return self._commands.get(name)

    def has_command(self, name: str) -> bool:
        """检查命令是否存在"""
        return name in self._aliases or name in self._commands

    def list_commands(self) -> List[str]:
        """列出所有命令名"""
        return list(self._commands.keys())

    def list_all_names(self) -> List[str]:
        """列出所有命令名和别名"""
        return list(self._commands.keys()) + list(self._aliases.keys())


class SimpleCommand(Command):
    """简单命令基类 - 用于无需复杂逻辑的命令"""

    async def execute(self, args: List[str]) -> CommandResult:
        """默认实现调用 _execute"""
        return self._execute(args)

    @abstractmethod
    def _execute(self, args: List[str]) -> CommandResult:
        """子类实现具体逻辑（同步方法）"""
        pass


class CommandFactory:
    """
    命令工厂 - 负责创建命令实例

    使用 Factory 模式实现命令的延迟创建和依赖注入
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        plugin_service: PluginService,
        plugin_executor: PluginExecutor,
        chinese: bool = True,
    ):
        """
        初始化命令工厂

        Args:
            config_manager: 配置管理器
            plugin_service: 插件服务
            plugin_executor: 插件执行器
            chinese: 是否使用中文
        """
        self.config_manager = config_manager
        self.plugin_service = plugin_service
        self.plugin_executor = plugin_executor
        self.chinese = chinese
        self.i18n = I18nManager(chinese=chinese)
        self.formatter = OutputFormatter(chinese=chinese)
        self.constants = GlobalConstants()

        # 命令创建器映射 - 延迟导入避免循环依赖
        self._creators: Dict[str, Any] = {}
        self._register_creators()

    def _register_creators(self):
        """注册所有命令创建器"""
        from .help_command import HelpCommand
        from .version_command import VersionCommand
        from .plugin_list_command import PluginListCommand
        from .plugin_info_command import PluginInfoCommand
        from .plugin_enable_command import PluginEnableCommand
        from .plugin_disable_command import PluginDisableCommand
        from .status_command import StatusCommand
        from .doctor_command import DoctorCommand
        from .refresh_command import RefreshCommand
        from .parser_command import ParserCommand

        # 注册系统命令创建器
        self._creators = {
            "help": HelpCommand,
            "version": VersionCommand,
            "status": StatusCommand,
            "doctor": DoctorCommand,
            "refresh": RefreshCommand,
            "parser": ParserCommand,
            "plugin:list": PluginListCommand,
            "plugin:info": PluginInfoCommand,
            "plugin:enable": PluginEnableCommand,
            "plugin:disable": PluginDisableCommand,
        }

    def create(self, command_type: str) -> Command:
        """
        创建命令实例

        Args:
            command_type: 命令类型（如 'help', 'version', 'plugin:list'）

        Returns:
            Command: 命令实例

        Raises:
            ValueError: 未知的命令类型
        """
        creator = self._creators.get(command_type)
        if creator is None:
            raise ValueError(f"Unknown command type: {command_type}")

        # 使用统一的依赖注入创建命令
        return creator(
            self.config_manager,
            self.plugin_service,
            self.plugin_executor,
            self.i18n,
            self.formatter,
            self.constants,
            self.chinese,
        )

    def create_all(self) -> List[Command]:
        """
        创建所有注册的命令

        Returns:
            List[Command]: 所有命令实例列表
        """
        return [self.create(cmd_type) for cmd_type in self._creators.keys()]

    def register_command_type(self, command_type: str, command_class: type) -> None:
        """
        注册新的命令类型（用于插件扩展）

        Args:
            command_type: 命令类型名称
            command_class: 命令类
        """
        self._creators[command_type] = command_class

    def has_command_type(self, command_type: str) -> bool:
        """检查命令类型是否存在"""
        return command_type in self._creators


# 命令工厂函数（兼容旧代码）
def create_command_registry(
    config_manager: ConfigManager,
    plugin_service: PluginService,
    plugin_executor: PluginExecutor,
    chinese: bool = True,
) -> CommandRegistry:
    """
    创建并配置命令注册表（使用 CommandFactory）

    Args:
        config_manager: 配置管理器
        plugin_service: 插件服务
        plugin_executor: 插件执行器
        chinese: 是否使用中文

    Returns:
        CommandRegistry: 配置好的命令注册表
    """
    factory = CommandFactory(config_manager, plugin_service, plugin_executor, chinese)

    registry = CommandRegistry()
    commands = factory.create_all()
    registry.register_multiple(commands)

    return registry
