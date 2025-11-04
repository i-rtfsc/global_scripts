"""
Dependency Injection Configuration
依赖注入配置 - 配置全局容器

在应用启动时调用 configure_container() 来设置所有依赖关系
"""

from pathlib import Path
from typing import Optional

from .container import Container, get_container
from .config_manager import ConfigManager
from .plugin_manager import PluginManager
from .constants import GlobalConstants
from .command_executor import CommandExecutor, get_command_executor
from ..utils.process_executor import ProcessExecutor, get_process_executor
from ..utils.i18n import I18nManager
from ..plugins.interfaces import IPluginLoader, IPluginManager, ICommandExecutor
from ..plugins.loader import RefactoredPluginLoader
from ..plugins.discovery import PluginDiscovery
from ..plugins.validators import PluginValidator


def configure_container(
    container: Optional[Container] = None,
    plugins_root: Optional[Path] = None,
    chinese: bool = True,
) -> Container:
    """
    配置依赖注入容器

    Args:
        container: 容器实例，None则使用全局容器
        plugins_root: 插件根目录
        chinese: 是否使用中文

    Returns:
        Container: 配置好的容器
    """
    if container is None:
        container = get_container()

    # ============= 核心组件（单例） =============

    # 常量
    constants = GlobalConstants()
    container.register_singleton(GlobalConstants, constants)

    # 配置管理器
    config_manager = ConfigManager()
    container.register_singleton(ConfigManager, config_manager)

    # 国际化
    i18n = I18nManager(chinese=chinese)
    container.register_singleton(I18nManager, i18n)

    # ============= 执行器（单例） =============

    # 进程执行器
    process_executor = get_process_executor()
    container.register_singleton(ProcessExecutor, process_executor)

    # 命令执行器
    command_executor = get_command_executor()
    container.register_singleton(CommandExecutor, command_executor)
    container.register_singleton(ICommandExecutor, command_executor)

    # ============= 插件系统（单例） =============

    # 插件根目录
    if plugins_root is None:
        plugins_root = config_manager.get_plugins_dir()

    # 插件加载器
    def create_plugin_loader():
        return RefactoredPluginLoader(plugins_root)

    container.register_factory(
        RefactoredPluginLoader, create_plugin_loader, singleton=True
    )
    container.register_factory(IPluginLoader, create_plugin_loader, singleton=True)

    # 插件发现器
    def create_plugin_discovery():
        return PluginDiscovery(plugins_root)

    container.register_factory(PluginDiscovery, create_plugin_discovery, singleton=True)

    # 插件验证器
    def create_plugin_validator():
        return PluginValidator()

    container.register_factory(PluginValidator, create_plugin_validator, singleton=True)

    # 插件管理器
    def create_plugin_manager():
        return PluginManager(config_manager=config_manager, plugins_root=plugins_root)

    container.register_factory(PluginManager, create_plugin_manager, singleton=True)
    container.register_factory(IPluginManager, create_plugin_manager, singleton=True)

    return container


def get_configured_container() -> Container:
    """
    获取配置好的全局容器

    如果容器未配置，则自动配置

    Returns:
        Container: 配置好的容器
    """
    container = get_container()

    # 检查是否已配置（通过检查关键依赖）
    if not container.has(GlobalConstants):
        configure_container(container)

    return container


# ============= 便捷函数 =============


def resolve(interface):
    """
    便捷解析函数

    用法:
    ```python
    from gscripts.core.di_config import resolve
    from gscripts.core.config_manager import ConfigManager

    config = resolve(ConfigManager)
    ```
    """
    container = get_configured_container()
    return container.resolve(interface)


def resolve_optional(interface):
    """便捷可选解析函数"""
    container = get_configured_container()
    return container.resolve_optional(interface)


__all__ = [
    "configure_container",
    "get_configured_container",
    "resolve",
    "resolve_optional",
]
