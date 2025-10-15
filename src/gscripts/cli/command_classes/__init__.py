"""
Command pattern implementation for Global Scripts CLI
命令模式实现 - 每个命令独立封装，使用 Factory 模式创建
"""

from .base import Command, CommandRegistry, CommandFactory, create_command_registry
from .help_command import HelpCommand
from .version_command import VersionCommand
from .plugin_list_command import PluginListCommand
from .plugin_info_command import PluginInfoCommand
from .status_command import StatusCommand
from .doctor_command import DoctorCommand
from .refresh_command import RefreshCommand
from .parser_command import ParserCommand

__all__ = [
    # Base classes
    'Command',
    'CommandRegistry',
    'CommandFactory',
    'create_command_registry',

    # Concrete commands
    'HelpCommand',
    'VersionCommand',
    'PluginListCommand',
    'PluginInfoCommand',
    'StatusCommand',
    'DoctorCommand',
    'RefreshCommand',
    'ParserCommand',
]
