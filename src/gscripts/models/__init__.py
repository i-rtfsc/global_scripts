"""
数据模型模块
统一定义系统中使用的数据结构
"""

from .result import CommandResult, ExecutionMetadata
from .plugin import PluginMetadata, PluginType, PluginPaths
from .function import FunctionInfo, FunctionType
from .config import ConfigSchema

__all__ = [
    "CommandResult",
    "ExecutionMetadata",
    "PluginMetadata",
    "PluginType",
    "PluginPaths",
    "FunctionInfo",
    "FunctionType",
    "ConfigSchema",
]
