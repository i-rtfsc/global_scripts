"""
Migration Compatibility Tests Configuration

Provides fixtures and utilities for testing behavioral equivalence
between legacy and new architecture.
"""

import pytest
import os
from pathlib import Path
from typing import Generator

# Test modes
SYSTEM_MODE = os.getenv('GS_TEST_SYSTEM', 'both')  # 'legacy', 'new', or 'both'


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Get project root directory"""
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def plugins_root(project_root: Path) -> Path:
    """Get plugins directory"""
    return project_root / "plugins"


@pytest.fixture(params=["legacy", "new"] if SYSTEM_MODE == "both" else [SYSTEM_MODE])
def system_type(request):
    """Parameterize tests to run against both legacy and new systems"""
    return request.param


@pytest.fixture
async def plugin_manager_legacy(plugins_root, tmp_path):
    """
    Provide legacy PluginManager instance for testing

    This fixture is used when system_type == 'legacy'
    """
    from gscripts.core.plugin_manager import PluginManager
    from gscripts.core.config_manager import ConfigManager

    # Use temporary config to avoid affecting user settings
    config_manager = ConfigManager()

    manager = PluginManager(
        plugins_root=plugins_root,
        config_manager=config_manager
    )

    await manager.initialize()
    yield manager


@pytest.fixture
async def plugin_service_new(plugins_root, tmp_path):
    """
    Provide new PluginService instance for testing

    This fixture is used when system_type == 'new'
    """
    from gscripts.application.services import PluginService
    from gscripts.infrastructure.persistence import PluginRepository, PluginLoader
    from gscripts.infrastructure import DIContainer, get_container, reset_container

    # Reset DI container for test isolation
    reset_container()
    container = get_container()

    # Get instances from DI container (already configured)
    from gscripts.domain.interfaces import IPluginRepository, IPluginLoader

    # For now, create instances manually
    # TODO: Use DI container properly
    loader = PluginLoader(plugins_root)
    repository = PluginRepository(loader)

    service = PluginService(
        plugin_loader=loader,
        plugin_repository=repository
    )

    # Initialize by loading plugins
    await service.load_all_plugins()

    yield service

    # Cleanup
    reset_container()


@pytest.fixture
async def plugin_system(system_type, plugin_manager_legacy, plugin_service_new):
    """
    Provide either legacy or new system based on parameterization

    This is the main fixture for compatibility tests.
    Tests use this fixture and it will automatically run against both systems.
    """
    if system_type == "legacy":
        yield {"type": "legacy", "system": plugin_manager_legacy}
    else:
        yield {"type": "new", "system": plugin_service_new}


# Pytest command line options
def pytest_addoption(parser):
    """Add custom command line options"""
    parser.addoption(
        "--legacy-system",
        action="store_true",
        help="Run tests only against legacy system"
    )
    parser.addoption(
        "--new-system",
        action="store_true",
        help="Run tests only against new system"
    )


def pytest_configure(config):
    """Configure test environment based on command line options"""
    global SYSTEM_MODE

    if config.getoption("--legacy-system"):
        SYSTEM_MODE = "legacy"
        os.environ['GS_TEST_SYSTEM'] = "legacy"
    elif config.getoption("--new-system"):
        SYSTEM_MODE = "new"
        os.environ['GS_TEST_SYSTEM'] = "new"
    else:
        SYSTEM_MODE = "both"
        os.environ['GS_TEST_SYSTEM'] = "both"


__all__ = [
    'system_type',
    'plugin_manager_legacy',
    'plugin_service_new',
    'plugin_system',
    'project_root',
    'plugins_root',
]
