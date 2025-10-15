"""
Core module initialization
"""

from .plugin_manager import PluginManager
from .command_executor import CommandExecutor
from .config_manager import ConfigManager

__all__ = ['PluginManager', 'CommandExecutor', 'ConfigManager']
