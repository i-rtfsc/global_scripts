"""
Plugins package
插件系统模块

提供插件的发现、加载、验证和执行功能
"""

from .base import BasePlugin
from .decorators import plugin_function, FunctionMetadata
from .loader import RefactoredPluginLoader
from .discovery import PluginDiscovery
from .validators import PluginValidator

__all__ = [
    # 实现类
    "BasePlugin",
    "RefactoredPluginLoader",
    "PluginDiscovery",
    "PluginValidator",
    # 装饰器
    "plugin_function",
    "FunctionMetadata",
]
