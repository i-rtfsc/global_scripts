"""
Persistence layer
Manages data persistence for plugins and configuration
"""

from .plugin_repository import PluginRepository
from .plugin_loader import PluginLoader

__all__ = [
    "PluginRepository",
    "PluginLoader",
]
