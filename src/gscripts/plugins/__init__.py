"""
Plugins package
插件系统模块

提供插件的发现、加载、验证和执行功能
Phase 4: 引入接口定义，提供类型安全
"""

from .interfaces import (
    # 核心接口
    IPlugin,
    IPluginLoader,
    IPluginManager,
    IPluginDiscovery,
    IPluginValidator,
    IFunctionParser,
    IConfigRepository,
    ICommandExecutor,

    # Observer 模式接口
    IPluginObserver,
    IObservablePluginManager,

    # 数据类型
    FunctionInfo,
    PluginMetadata,
    ValidationResult,
    PluginEvent,
    PluginEventData,

    # 类型别名
    PluginDict,
    FunctionDict,
    ConfigDict,

    # 辅助函数
    is_valid_plugin,
    is_valid_plugin_loader,
    is_valid_plugin_manager,
)

from .base import BasePlugin
from .decorators import plugin_function, FunctionMetadata
from .loader import RefactoredPluginLoader
from .discovery import PluginDiscovery
from .validators import PluginValidator

__all__ = [
    # 接口
    'IPlugin',
    'IPluginLoader',
    'IPluginManager',
    'IPluginDiscovery',
    'IPluginValidator',
    'IFunctionParser',
    'IConfigRepository',
    'ICommandExecutor',

    # Observer 模式接口
    'IPluginObserver',
    'IObservablePluginManager',

    # 数据类型
    'FunctionInfo',
    'PluginMetadata',
    'ValidationResult',
    'PluginEvent',
    'PluginEventData',

    # 类型别名
    'PluginDict',
    'FunctionDict',
    'ConfigDict',

    # 实现类
    'BasePlugin',
    'RefactoredPluginLoader',
    'PluginDiscovery',
    'PluginValidator',

    # 装饰器
    'plugin_function',
    'FunctionMetadata',

    # 辅助函数
    'is_valid_plugin',
    'is_valid_plugin_loader',
    'is_valid_plugin_manager',
]
