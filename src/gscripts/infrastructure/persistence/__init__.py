"""
Persistence layer
Manages data persistence for plugins and configuration
"""

from .plugin_repository import PluginRepository
from .config_repository import ConfigRepository
from .plugin_loader import PluginLoader

__all__ = [
    'PluginRepository',
    'ConfigRepository',
    'PluginLoader',
]
