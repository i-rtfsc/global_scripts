"""
Plugin lifecycle event models
插件生命周期事件模型

供插件执行器在加载/启停/执行等阶段向观察者广播事件之用。
历史上定义在 plugins/interfaces.py，已随接口契约收敛迁入 models/。
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from .result import CommandResult


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
    FUNCTION_EXECUTED = "function_executed"  # deprecated, use EXECUTED


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
