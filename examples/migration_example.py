"""
Migration Example: Using New Architecture
Shows how to migrate from old code to new DI-based architecture
"""

import asyncio
from pathlib import Path

# ============================================================================
# OLD WAY (Before Migration)
# ============================================================================

def old_way_example():
    """Example of old code pattern - direct instantiation"""
    from gscripts.core.config_manager import ConfigManager
    from gscripts.core.plugin_loader import PluginLoader

    # Tightly coupled - direct instantiation
    config_manager = ConfigManager()
    plugin_loader = PluginLoader(config_manager.get_plugins_dir())

    # Hard to test - depends on real filesystem
    plugins = asyncio.run(plugin_loader.load_all_plugins())

    return plugins


# ============================================================================
# NEW WAY (After Migration)
# ============================================================================

async def new_way_example():
    """Example of new code pattern - using DI container"""
    from gscripts.infrastructure import get_container, configure_services
    from gscripts.infrastructure.persistence import PluginRepository
    from gscripts.application.services import PluginService, ConfigService
    from gscripts.domain.interfaces import IPluginRepository
    from gscripts.core.constants import GlobalConstants

    # 1. Get or create DI container
    container = get_container()

    # 2. Configure services (only once at application startup)
    configure_services(
        container,
        use_mocks=False,  # Use real implementations
        plugins_dir=GlobalConstants.PLUGINS_DIR,
        config_path=GlobalConstants.CONFIG_FILE
    )

    # 3. Resolve services from container
    plugin_service = container.resolve(PluginService)
    config_service = container.resolve(ConfigService)

    # 4. Use services (loosely coupled, easy to test)
    plugins = await plugin_service.load_all_plugins()
    language = await config_service.get_language()

    print(f"Loaded {len(plugins)} plugins")
    print(f"Language: {language}")

    return plugins


# ============================================================================
# TESTING EXAMPLE
# ============================================================================

async def testing_example():
    """Example showing how easy testing becomes with DI"""
    from gscripts.infrastructure import DIContainer, configure_services
    from gscripts.application.services import ConfigService
    from gscripts.domain.interfaces import IEnvironment
    from pathlib import Path

    # Create test container with mocks
    test_container = DIContainer()
    configure_services(
        test_container,
        use_mocks=True,  # Use mock implementations
        plugins_dir=Path("/test/plugins"),
        config_path=Path("/test/config.json")
    )

    # Mock environment for testing
    mock_env = test_container.resolve(IEnvironment)
    mock_env.set("GS_LANGUAGE", "en")

    # Test the service
    config_service = test_container.resolve(ConfigService)
    language = await config_service.get_language()

    assert language == "en", "Should read from environment variable"
    print("✅ Test passed!")


# ============================================================================
# MIGRATION STEPS FOR CLI COMMANDS
# ============================================================================

class MigrationExample:
    """
    Step-by-step migration for CLI command classes
    """

    # BEFORE: Old command class
    class OldCommand:
        def __init__(self):
            from gscripts.core.config_manager import ConfigManager
            from gscripts.core.plugin_manager import PluginManager

            # Direct dependencies - hard to test
            self.config = ConfigManager()
            self.plugins = PluginManager(self.config.get_plugins_dir(), self.config)

        async def execute(self):
            plugins = await self.plugins.load_all_plugins()
            return f"Loaded {len(plugins)} plugins"

    # AFTER: New command class with DI
    class NewCommand:
        def __init__(self, plugin_service, config_service):
            """Dependencies injected - easy to test"""
            self.plugin_service = plugin_service
            self.config_service = config_service

        async def execute(self):
            plugins = await self.plugin_service.load_all_plugins()
            return f"Loaded {len(plugins)} plugins"

    @staticmethod
    async def show_migration():
        """Show how to use the new command"""
        from gscripts.infrastructure import get_container
        from gscripts.application.services import PluginService, ConfigService

        container = get_container()

        # Resolve dependencies
        plugin_service = container.resolve(PluginService)
        config_service = container.resolve(ConfigService)

        # Create command with injected dependencies
        command = MigrationExample.NewCommand(plugin_service, config_service)
        result = await command.execute()

        print(result)


# ============================================================================
# KEY BENEFITS OF NEW ARCHITECTURE
# ============================================================================

"""
Benefits of the new architecture:

1. **Testability**: Easy to inject mocks for testing
2. **Loose Coupling**: Components depend on interfaces, not implementations
3. **Single Responsibility**: Each service has one clear purpose
4. **Maintainability**: Changes to one component don't break others
5. **Extensibility**: Easy to swap implementations (e.g., different storage backends)

Migration Checklist:
[ ] Identify classes using ConfigManager directly
[ ] Identify classes using PluginLoader/PluginManager directly
[ ] Replace with ConfigService/PluginService
[ ] Inject services via constructor instead of creating them
[ ] Update tests to use mock container
[ ] Verify functionality with integration tests
"""


if __name__ == "__main__":
    print("=" * 80)
    print("NEW WAY: Using DI Container")
    print("=" * 80)
    asyncio.run(new_way_example())

    print("\n" + "=" * 80)
    print("TESTING: Easy with Mocks")
    print("=" * 80)
    asyncio.run(testing_example())

    print("\n" + "=" * 80)
    print("MIGRATION: CLI Command Example")
    print("=" * 80)
    asyncio.run(MigrationExample.show_migration())
