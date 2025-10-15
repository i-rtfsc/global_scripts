"""
仓储接口定义
遵循依赖反转原则，高层模块依赖这些抽象接口
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from pathlib import Path


class IPluginRepository(ABC):
    """插件仓储接口"""

    @abstractmethod
    async def get_all(self) -> List[Any]:
        """获取所有插件"""
        pass

    @abstractmethod
    async def get_by_name(self, name: str) -> Optional[Any]:
        """根据名称获取插件"""
        pass

    @abstractmethod
    async def save(self, plugin: Any) -> None:
        """保存插件状态"""
        pass

    @abstractmethod
    async def delete(self, name: str) -> bool:
        """删除插件"""
        pass


class IConfigRepository(ABC):
    """配置仓储接口"""

    @abstractmethod
    async def load(self) -> Dict[str, Any]:
        """加载配置"""
        pass

    @abstractmethod
    async def save(self, config: Dict[str, Any]) -> None:
        """保存配置"""
        pass

    @abstractmethod
    async def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any) -> None:
        """设置配置项"""
        pass


class IPluginLoader(ABC):
    """插件加载器接口"""

    @abstractmethod
    async def load_all_plugins(self, include_examples: bool = False) -> Dict[str, Any]:
        """加载所有插件"""
        pass

    @abstractmethod
    async def load_plugin(self, plugin_name: str, **kwargs) -> Optional[Any]:
        """加载单个插件"""
        pass

    @abstractmethod
    def get_loaded_plugins(self) -> Dict[str, Any]:
        """获取已加载的插件"""
        pass


__all__ = [
    'IPluginRepository',
    'IConfigRepository',
    'IPluginLoader',
]
