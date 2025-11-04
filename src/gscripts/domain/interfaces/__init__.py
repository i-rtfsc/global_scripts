"""Domain interfaces"""

from .repositories import (
    IPluginRepository,
    IConfigRepository,
    IPluginLoader,
)

from .services import (
    IProcessExecutor,
    ICommandExecutor,
    IFileSystem,
    IEnvironment,
)

__all__ = [
    "IPluginRepository",
    "IConfigRepository",
    "IPluginLoader",
    "IProcessExecutor",
    "ICommandExecutor",
    "IFileSystem",
    "IEnvironment",
]
