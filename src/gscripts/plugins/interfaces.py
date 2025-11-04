"""
Plugin System Interfaces
插件系统接口定义 - 使用 Protocol 实现类型安全的鸭子类型

这些接口定义了插件系统的核心契约，使得：
1. 类型检查更安全（mypy等工具可以检查）
2. 代码更易理解（明确的接口契约）
3. 解耦更彻底（依赖接口而非实现）
4. 测试更容易（可以创建mock实现）
"""

from __future__ import annotations  # Enable postponed evaluation of annotations

from typing import Protocol, Dict, List, Optional, Any, runtime_checkable, TYPE_CHECKING
from pathlib import Path
from dataclasses import dataclass
from enum import Enum

# Use TYPE_CHECKING to avoid circular import at runtime
if TYPE_CHECKING:
    from gscripts.models.result import CommandResult


# ============= 数据类型定义 =============


@dataclass
class FunctionInfo:
    """函数信息"""

    name: str
    description: str
    usage: str
    examples: List[str]
    args: List[str]
    plugin_name: str
    function_type: str  # 'python', 'shell', 'json'
    file_path: Optional[Path] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PluginMetadata:
    """插件元数据"""

    name: str
    version: str
    author: str
    description: str
    plugin_type: str  # 'python', 'shell', 'json', 'config', 'hybrid'
    enabled: bool
    priority: int
    plugin_dir: Path
    dependencies: List[str] = None
    keywords: List[str] = None


@dataclass
class ValidationResult:
    """验证结果"""

    valid: bool
    errors: List[str]
    warnings: List[str]


class PluginEvent(Enum):
    """插件生命周期事件"""

    LOADING = "loading"  # 插件正在加载
    LOADED = "loaded"  # 插件已加载
    UNLOADED = "unloaded"  # 插件已卸载
    ENABLED = "enabled"  # 插件已启用
    DISABLED = "disabled"  # 插件已禁用
    RELOADED = "reloaded"  # 插件已重新加载
    EXECUTING = "executing"  # 函数正在执行
    EXECUTED = "executed"  # 函数已执行
    FUNCTION_EXECUTED = "function_executed"  # 函数已执行 (deprecated, use EXECUTED)


@dataclass
class PluginEventData:
    """插件事件数据"""

    event: PluginEvent
    plugin_name: str
    plugin: Optional[Any] = None  # IPlugin instance
    function_name: Optional[str] = None
    result: Optional[CommandResult] = None
    error: Optional[Exception] = None
    metadata: Optional[Dict[str, Any]] = None


# ============= 核心接口定义 =============


@runtime_checkable
class IPlugin(Protocol):
    """插件接口 - 所有插件必须实现的核心契约

    使用Protocol而非ABC，支持鸭子类型和结构子类型化
    """

    # 必需属性
    name: str
    version: str
    enabled: bool
    plugin_type: str
    plugin_dir: Path
    functions: Dict[str, Any]

    # 可选属性
    author: Optional[str]
    description: Optional[str]
    priority: Optional[int]

    async def execute_function(self, func_name: str, args: List[str]) -> CommandResult:
        """
        执行插件函数

        Args:
            func_name: 函数名
            args: 参数列表

        Returns:
            CommandResult: 执行结果
        """
        ...

    def get_function_info(self, func_name: str) -> Optional[FunctionInfo]:
        """获取函数信息"""
        ...

    def validate(self) -> ValidationResult:
        """验证插件配置和依赖"""
        ...


@runtime_checkable
class IPluginDiscovery(Protocol):
    """插件发现接口 - 负责扫描和发现插件"""

    def discover_all_plugins(
        self, plugins_root: Path, include_examples: bool = False
    ) -> List[Path]:
        """
        发现所有插件目录

        Args:
            plugins_root: 插件根目录
            include_examples: 是否包含示例插件

        Returns:
            List[Path]: 插件目录列表
        """
        ...

    def scan_plugin_directory(self, plugin_dir: Path) -> Dict[str, Any]:
        """
        扫描单个插件目录

        Args:
            plugin_dir: 插件目录

        Returns:
            Dict: 插件扫描结果（包含类型、文件等信息）
        """
        ...


@runtime_checkable
class IPluginValidator(Protocol):
    """插件验证接口 - 负责验证插件的有效性"""

    def validate_plugin_directory(self, plugin_dir: Path) -> ValidationResult:
        """验证插件目录结构"""
        ...

    def validate_plugin_metadata(
        self, metadata: Dict[str, Any], plugin_name: str
    ) -> ValidationResult:
        """验证插件元数据"""
        ...

    def validate_plugin_dependencies(
        self, plugin: IPlugin, available_plugins: Dict[str, IPlugin]
    ) -> ValidationResult:
        """验证插件依赖"""
        ...


@runtime_checkable
class IFunctionParser(Protocol):
    """函数解析器接口 - 负责从文件中解析函数定义"""

    def can_parse(self, file: Path) -> bool:
        """判断是否能解析该文件"""
        ...

    async def parse(self, file: Path, plugin_name: str) -> List[FunctionInfo]:
        """
        解析文件中的函数

        Args:
            file: 文件路径
            plugin_name: 插件名称

        Returns:
            List[FunctionInfo]: 函数信息列表
        """
        ...


@runtime_checkable
class IPluginLoader(Protocol):
    """插件加载器接口 - 负责加载插件"""

    async def load_plugin(self, plugin_dir: Path) -> Optional[IPlugin]:
        """
        加载单个插件

        Args:
            plugin_dir: 插件目录

        Returns:
            IPlugin: 插件实例，失败返回None
        """
        ...

    async def load_all_plugins(
        self, plugins_root: Path, include_examples: bool = False
    ) -> Dict[str, IPlugin]:
        """
        加载所有插件

        Args:
            plugins_root: 插件根目录
            include_examples: 是否包含示例插件

        Returns:
            Dict[str, IPlugin]: 插件字典 {plugin_name: plugin}
        """
        ...

    def unload_plugin(self, plugin_name: str) -> bool:
        """卸载插件"""
        ...


@runtime_checkable
class IPluginManager(Protocol):
    """插件管理器接口 - 负责插件的生命周期管理"""

    plugins: Dict[str, IPlugin]

    async def initialize(self) -> bool:
        """初始化插件管理器"""
        ...

    def get_plugin(self, name: str) -> Optional[IPlugin]:
        """获取插件"""
        ...

    def is_plugin_enabled(self, name: str) -> bool:
        """检查插件是否启用"""
        ...

    async def enable_plugin(self, name: str) -> bool:
        """启用插件"""
        ...

    async def disable_plugin(self, name: str) -> bool:
        """禁用插件"""
        ...

    async def reload_plugin(self, name: str) -> bool:
        """重新加载插件"""
        ...

    async def execute_plugin_function(
        self, plugin_name: str, function_name: str, args: List[str]
    ) -> CommandResult:
        """
        执行插件函数

        Args:
            plugin_name: 插件名
            function_name: 函数名
            args: 参数

        Returns:
            CommandResult: 执行结果
        """
        ...

    async def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        ...


@runtime_checkable
class IConfigRepository(Protocol):
    """配置仓库接口 - 负责配置的读写"""

    def load(self) -> Dict[str, Any]:
        """加载配置"""
        ...

    def save(self, config: Dict[str, Any]) -> bool:
        """保存配置"""
        ...

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        ...

    def set(self, key: str, value: Any) -> bool:
        """设置配置项"""
        ...


@runtime_checkable
class ICommandExecutor(Protocol):
    """命令执行器接口 - 负责执行shell命令"""

    async def execute(
        self,
        command: str | List[str],
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> CommandResult:
        """执行命令"""
        ...

    async def execute_safe(self, command: str | List[str], **kwargs) -> CommandResult:
        """安全执行命令（仅白名单）"""
        ...


# ============= 类型别名 =============

PluginDict = Dict[str, IPlugin]
FunctionDict = Dict[str, FunctionInfo]
ConfigDict = Dict[str, Any]


# ============= 辅助函数 =============


def is_valid_plugin(obj: Any) -> bool:
    """检查对象是否实现了IPlugin接口"""
    return isinstance(obj, IPlugin)


def is_valid_plugin_loader(obj: Any) -> bool:
    """检查对象是否实现了IPluginLoader接口"""
    return isinstance(obj, IPluginLoader)


def is_valid_plugin_manager(obj: Any) -> bool:
    """检查对象是否实现了IPluginManager接口"""
    return isinstance(obj, IPluginManager)


# ============= Observer 模式接口 =============


@runtime_checkable
class IPluginObserver(Protocol):
    """
    插件观察者接口 - Observer 模式

    用于监听插件生命周期事件，如加载、启用、禁用等。
    观察者可以实现此接口来响应插件事件。

    使用场景：
    - 缓存失效：当插件启用/禁用时清除缓存
    - 日志记录：记录插件生命周期事件
    - 性能监控：跟踪插件加载和执行时间
    - 事件通知：向外部系统发送插件状态变化通知
    """

    def on_plugin_event(self, event_data: PluginEventData) -> None:
        """
        插件事件回调

        Args:
            event_data: 事件数据，包含事件类型、插件信息等
        """
        ...

    @property
    def observer_name(self) -> str:
        """观察者名称"""
        ...


@runtime_checkable
class IObservablePluginManager(Protocol):
    """
    可观察的插件管理器接口

    扩展 IPluginManager 以支持观察者模式
    """

    def register_observer(self, observer: IPluginObserver) -> None:
        """
        注册观察者

        Args:
            observer: 观察者实例
        """
        ...

    def unregister_observer(self, observer: IPluginObserver) -> None:
        """
        取消注册观察者

        Args:
            observer: 观察者实例
        """
        ...

    def notify_observers(self, event_data: PluginEventData) -> None:
        """
        通知所有观察者

        Args:
            event_data: 事件数据
        """
        ...
