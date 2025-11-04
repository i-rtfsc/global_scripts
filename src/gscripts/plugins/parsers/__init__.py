"""
函数解析器基类和接口
使用策略模式处理不同类型的函数解析
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional, Type, Callable
from dataclasses import dataclass, field
from functools import wraps


@dataclass
class ParserMetadata:
    """解析器元数据"""

    name: str
    version: str = "1.0.0"
    supported_extensions: List[str] = field(default_factory=list)
    priority: int = 100
    description: str = ""


def parser_metadata(
    name: str,
    version: str = "1.0.0",
    supported_extensions: Optional[List[str]] = None,
    priority: int = 100,
    description: str = "",
) -> Callable:
    """
    解析器元数据装饰器

    使用示例:
        @parser_metadata(
            name="yaml",
            version="1.0.0",
            supported_extensions=[".yaml", ".yml"],
            priority=100,
            description="YAML configuration parser"
        )
        class YAMLParser(FunctionParser):
            pass
    """

    def decorator(cls: Type[FunctionParser]) -> Type[FunctionParser]:
        cls._metadata = ParserMetadata(
            name=name,
            version=version,
            supported_extensions=supported_extensions or [],
            priority=priority,
            description=description,
        )
        return cls

    return decorator


@dataclass
class FunctionInfo:
    """函数信息数据类"""

    name: str
    description: str
    command: str
    type: str  # 'python', 'shell', 'config'
    args: List[str] = None
    options: Dict[str, Any] = None
    examples: List[str] = None
    plugin_name: str = ""
    subplugin_name: str = ""

    def __post_init__(self):
        if self.args is None:
            self.args = []
        if self.options is None:
            self.options = {}
        if self.examples is None:
            self.examples = []


class FunctionParser(ABC):
    """
    函数解析器抽象基类

    职责：
    - 定义解析接口
    - 子类实现具体解析逻辑
    """

    _metadata: Optional[ParserMetadata] = None

    @property
    def metadata(self) -> Optional[ParserMetadata]:
        """获取解析器元数据"""
        return getattr(self.__class__, "_metadata", None)

    @abstractmethod
    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        """
        解析文件中的函数

        Args:
            file: 文件路径
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            List[FunctionInfo]: 函数信息列表
        """
        pass

    @abstractmethod
    def can_parse(self, file: Path) -> bool:
        """
        检查是否能解析该文件

        Args:
            file: 文件路径

        Returns:
            bool: 是否支持解析
        """
        pass


@dataclass
class _RegisteredParser:
    """内部使用的解析器注册信息"""

    name: str
    parser: FunctionParser
    priority: int
    enabled: bool = True


class FunctionParserRegistry:
    """
    函数解析器注册表

    职责：
    - 管理所有解析器
    - 根据文件类型选择合适的解析器
    - 支持优先级、启用/禁用、别名等高级功能
    """

    def __init__(self):
        """初始化解析器注册表"""
        self._parsers: Dict[str, _RegisteredParser] = {}
        self._aliases: Dict[str, str] = {}

    def register(
        self,
        parser: FunctionParser,
        name: Optional[str] = None,
        priority: Optional[int] = None,
    ) -> None:
        """
        注册解析器

        Args:
            parser: 解析器实例
            name: 解析器名称（如果未提供，从元数据获取）
            priority: 优先级（如果未提供，从元数据获取或使用100）
        """
        # 获取解析器名称
        if name is None:
            metadata = parser.metadata
            if metadata:
                name = metadata.name
            else:
                name = parser.__class__.__name__

        # 获取优先级
        if priority is None:
            metadata = parser.metadata
            if metadata:
                priority = metadata.priority
            else:
                priority = 100

        # 注册解析器
        self._parsers[name] = _RegisteredParser(
            name=name, parser=parser, priority=priority, enabled=True
        )

    def register_by_name(self, name: str, parser_class: Type[FunctionParser]) -> None:
        """
        按名称注册解析器类

        Args:
            name: 解析器名称
            parser_class: 解析器类
        """
        parser = parser_class()
        self.register(parser, name=name)

    def unregister(self, name: str) -> None:
        """
        注销解析器

        Args:
            name: 解析器名称
        """
        if name in self._parsers:
            del self._parsers[name]

        # 清理相关别名
        aliases_to_remove = [
            alias for alias, target in self._aliases.items() if target == name
        ]
        for alias in aliases_to_remove:
            del self._aliases[alias]

    def enable(self, name: str) -> None:
        """
        启用解析器

        Args:
            name: 解析器名称
        """
        if name in self._parsers:
            self._parsers[name].enabled = True

    def disable(self, name: str) -> None:
        """
        禁用解析器

        Args:
            name: 解析器名称
        """
        if name in self._parsers:
            self._parsers[name].enabled = False

    def register_alias(self, alias: str, target: str) -> None:
        """
        注册解析器别名

        Args:
            alias: 别名
            target: 目标解析器名称
        """
        if target in self._parsers:
            self._aliases[alias] = target

    def list_parsers(self) -> List[Dict[str, Any]]:
        """
        列出所有已注册的解析器

        Returns:
            解析器信息列表
        """
        result = []
        for name, registered in self._parsers.items():
            metadata = registered.parser.metadata
            info = {
                "name": name,
                "priority": registered.priority,
                "enabled": registered.enabled,
                "class": registered.parser.__class__.__name__,
            }
            if metadata:
                info.update(
                    {
                        "version": metadata.version,
                        "supported_extensions": metadata.supported_extensions,
                        "description": metadata.description,
                    }
                )
            result.append(info)
        return sorted(result, key=lambda x: x["priority"])

    def get_parser_info(self, name: str) -> Optional[Dict[str, Any]]:
        """
        获取指定解析器的详细信息

        Args:
            name: 解析器名称

        Returns:
            解析器信息字典，如果不存在返回None
        """
        # 检查别名
        resolved_name = self._aliases.get(name, name)

        if resolved_name not in self._parsers:
            return None

        registered = self._parsers[resolved_name]
        metadata = registered.parser.metadata

        info = {
            "name": resolved_name,
            "priority": registered.priority,
            "enabled": registered.enabled,
            "class": registered.parser.__class__.__name__,
            "instance": registered.parser,
        }

        if metadata:
            info.update(
                {
                    "version": metadata.version,
                    "supported_extensions": metadata.supported_extensions,
                    "description": metadata.description,
                }
            )

        return info

    def get(self, name: str) -> Optional[FunctionParser]:
        """
        根据名称获取解析器实例

        Args:
            name: 解析器名称

        Returns:
            解析器实例，如果不存在或被禁用返回None
        """
        # 检查别名
        resolved_name = self._aliases.get(name, name)

        if resolved_name in self._parsers:
            registered = self._parsers[resolved_name]
            if registered.enabled:
                return registered.parser

        return None

    def get_parser(self, file: Path) -> FunctionParser:
        """
        根据文件获取合适的解析器（按优先级排序）

        Args:
            file: 文件路径

        Returns:
            FunctionParser: 解析器实例

        Raises:
            ValueError: 找不到合适的解析器
        """
        # 按优先级排序（数字越小优先级越高）
        sorted_parsers = sorted(self._parsers.values(), key=lambda x: x.priority)

        # 遍历所有启用的解析器
        for registered in sorted_parsers:
            if registered.enabled and registered.parser.can_parse(file):
                return registered.parser

        raise ValueError(f"No parser found for file: {file}")

    def parse_all(
        self, files: List[Path], plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        """
        解析多个文件

        Args:
            files: 文件列表
            plugin_name: 插件名称
            subplugin_name: 子插件名称

        Returns:
            List[FunctionInfo]: 所有函数信息
        """
        import asyncio

        async def parse_files():
            tasks = []
            for file in files:
                try:
                    parser = self.get_parser(file)
                    tasks.append(parser.parse(file, plugin_name, subplugin_name))
                except ValueError:
                    # 跳过无法解析的文件
                    continue

            results = await asyncio.gather(*tasks, return_exceptions=True)

            functions = []
            for result in results:
                if isinstance(result, list):
                    functions.extend(result)

            return functions

        # 运行异步解析
        try:
            loop = asyncio.get_running_loop()
            # Already in async context - we need nest_asyncio
            import nest_asyncio

            nest_asyncio.apply()
            return asyncio.run(parse_files())
        except RuntimeError:
            # No event loop running, create one
            return asyncio.run(parse_files())


# Export discovery module
from .discovery import ParserDiscovery

__all__ = [
    "FunctionInfo",
    "FunctionParser",
    "FunctionParserRegistry",
    "ParserMetadata",
    "parser_metadata",
    "ParserDiscovery",
]
