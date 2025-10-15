"""
服务配置
配置DI容器，注册所有服务
"""

from pathlib import Path
from ..domain.interfaces import (
    IFileSystem,
    IEnvironment,
    IProcessExecutor,
    IPluginRepository,
    IConfigRepository,
    IPluginLoader,
)
from ..application.services import ConfigService, PluginService, PluginExecutor
from .di import DIContainer
from .filesystem import RealFileSystem, SystemEnvironment
from .execution import ProcessExecutor
from .persistence import PluginRepository, ConfigRepository, PluginLoader


def configure_services(
    container: DIContainer,
    use_mocks: bool = False,
    plugins_dir: Path = None,
    config_path: Path = None,
    router_cache_path: Path = None
) -> None:
    """配置服务容器

    Args:
        container: DI容器
        use_mocks: 是否使用模拟实现（用于测试）
        plugins_dir: 插件目录路径
        config_path: 配置文件路径
        router_cache_path: Router缓存文件路径（router.json）
    """
    # Set default paths if not provided
    if plugins_dir is None:
        from ..core.constants import GlobalConstants
        plugins_dir = GlobalConstants.PLUGINS_DIR

    if config_path is None:
        from ..core.constants import GlobalConstants
        config_path = GlobalConstants.CONFIG_FILE

    if router_cache_path is None:
        from ..core.constants import GlobalConstants
        router_cache_path = GlobalConstants.GS_HOME / 'cache' / 'router.json'

    if use_mocks:
        # 测试环境：使用模拟实现
        from .filesystem import InMemoryFileSystem, MockEnvironment

        filesystem = InMemoryFileSystem()
        environment = MockEnvironment()

        container.register(
            IFileSystem,
            lambda: filesystem,
            singleton=True
        )
        container.register(
            IEnvironment,
            lambda: environment,
            singleton=True
        )
    else:
        # 生产环境：使用真实实现
        filesystem = RealFileSystem()
        environment = SystemEnvironment()

        container.register(
            IFileSystem,
            lambda: filesystem,
            singleton=True
        )
        container.register(
            IEnvironment,
            lambda: environment,
            singleton=True
        )

    # ProcessExecutor（生产和测试共用）
    container.register(
        IProcessExecutor,
        lambda: ProcessExecutor(),
        singleton=True
    )

    # Repositories
    container.register(
        IPluginRepository,
        lambda: PluginRepository(
            container.resolve(IFileSystem),
            plugins_dir,
            router_cache_path
        ),
        singleton=True
    )

    container.register(
        IConfigRepository,
        lambda: ConfigRepository(
            container.resolve(IFileSystem),
            config_path
        ),
        singleton=True
    )

    # Plugin Loader
    container.register(
        IPluginLoader,
        lambda: PluginLoader(
            container.resolve(IPluginRepository),
            plugins_dir
        ),
        singleton=True
    )

    # Application Services
    container.register(
        ConfigService,
        lambda: ConfigService(
            container.resolve(IConfigRepository),
            container.resolve(IEnvironment)
        ),
        singleton=True
    )

    container.register(
        PluginService,
        lambda: PluginService(
            container.resolve(IPluginLoader),
            container.resolve(IPluginRepository)
        ),
        singleton=True
    )

    container.register(
        PluginExecutor,
        lambda: PluginExecutor(
            container.resolve(IPluginLoader),
            container.resolve(IProcessExecutor)
        ),
        singleton=True
    )


__all__ = ['configure_services']
