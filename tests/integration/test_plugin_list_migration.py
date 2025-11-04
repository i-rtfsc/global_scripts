"""
Integration Test for New Architecture Migration
Tests the plugin list command using the new DI-based approach
"""

import pytest
from pathlib import Path

from src.gscripts.infrastructure import DIContainer, configure_services
from src.gscripts.application.services import PluginService
from src.gscripts.domain.interfaces import IFileSystem
from src.gscripts.cli.command_classes.plugin_list_command import (
    PluginListCommand,
    create_plugin_list_command,
)


@pytest.fixture
def test_container_with_plugins():
    """Create test container with mock plugins"""
    container = DIContainer()
    plugins_dir = Path("/test/plugins")
    config_path = Path("/test/gs.json")

    configure_services(
        container, use_mocks=True, plugins_dir=plugins_dir, config_path=config_path
    )

    # Setup mock plugins
    fs = container.resolve(IFileSystem)

    # Plugin 1: Enabled system plugin
    fs.write_json(
        plugins_dir / "system_plugin" / "plugin.json",
        {
            "name": "system_plugin",
            "version": "1.0.0",
            "description": {"zh": "系统插件", "en": "System Plugin"},
            "enabled": True,
            "priority": 10,
            "category": "system",
        },
    )

    # Plugin 2: Disabled plugin
    fs.write_json(
        plugins_dir / "disabled_plugin" / "plugin.json",
        {
            "name": "disabled_plugin",
            "version": "0.5.0",
            "description": {"zh": "已禁用插件", "en": "Disabled Plugin"},
            "enabled": False,
            "priority": 50,
        },
    )

    # Plugin 3: Enabled user plugin
    fs.write_json(
        plugins_dir / "user_plugin" / "plugin.json",
        {
            "name": "user_plugin",
            "version": "2.0.0",
            "description": "User plugin",
            "enabled": True,
            "priority": 30,
        },
    )

    return container


class TestPluginListCommand:
    """Integration tests for plugin list command"""

    @pytest.mark.asyncio
    async def test_command_lists_enabled_and_disabled_plugins(
        self, test_container_with_plugins
    ):
        """Test that command correctly lists enabled and disabled plugins"""
        # Resolve service
        plugin_service = test_container_with_plugins.resolve(PluginService)

        # Create command with mock formatter and i18n
        class MockFormatter:
            def __init__(self):
                self.enabled = []
                self.disabled = []

            def print_plugin_list(self, enabled, disabled):
                self.enabled = enabled
                self.disabled = disabled

        class MockI18n:
            def get_message(self, key):
                return key

        class MockConstants:
            EXIT_GENERAL_ERROR = 1

        formatter = MockFormatter()
        i18n = MockI18n()
        constants = MockConstants()

        command = PluginListCommand(
            plugin_service=plugin_service,
            formatter=formatter,
            i18n=i18n,
            constants=constants,
            chinese=True,
        )

        # Execute command
        result = await command.execute([])

        # Verify result
        assert result.success is True

        # Verify enabled plugins
        assert len(formatter.enabled) == 2
        enabled_names = [p["name"] for p in formatter.enabled]
        assert "system_plugin" in enabled_names
        assert "user_plugin" in enabled_names

        # Verify disabled plugins
        assert len(formatter.disabled) == 1
        assert formatter.disabled[0]["name"] == "disabled_plugin"

    @pytest.mark.asyncio
    async def test_command_handles_no_plugins(self):
        """Test command with no plugins"""
        # Create empty container
        container = DIContainer()
        configure_services(
            container,
            use_mocks=True,
            plugins_dir=Path("/empty/plugins"),
            config_path=Path("/empty/config.json"),
        )

        plugin_service = container.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return "No plugins" if "no_plugins" in key else key

        command = PluginListCommand(
            plugin_service=plugin_service, i18n=MockI18n(), chinese=True
        )

        result = await command.execute([])

        assert result.success is True
        assert "No plugins" in result.message

    @pytest.mark.asyncio
    async def test_factory_function_creates_command(self, test_container_with_plugins):
        """Test factory function for creating command"""
        plugin_service = test_container_with_plugins.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return key

        command = create_plugin_list_command(
            plugin_service=plugin_service, i18n=MockI18n(), chinese=True
        )

        assert isinstance(command, PluginListCommand)
        assert command.plugin_service is plugin_service

    @pytest.mark.asyncio
    async def test_plugin_metadata_conversion(self, test_container_with_plugins):
        """Test conversion from metadata to display info"""
        plugin_service = test_container_with_plugins.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return "system" if "system" in key else key

        class MockFormatter:
            def print_plugin_list(self, enabled, disabled):
                self.enabled = enabled

        formatter = MockFormatter()
        command = PluginListCommand(
            plugin_service=plugin_service,
            formatter=formatter,
            i18n=MockI18n(),
            chinese=True,
        )

        await command.execute([])

        # Check that metadata was properly converted
        system_plugin = next(
            (p for p in formatter.enabled if p["name"] == "system_plugin"), None
        )

        assert system_plugin is not None
        assert system_plugin["version"] == "1.0.0"
        assert system_plugin["priority"] == 10
        assert "系统插件" in system_plugin["description"]


class TestMigrationComparison:
    """
    Tests comparing old vs new approach

    Demonstrates the benefits of new architecture
    """

    @pytest.mark.asyncio
    async def test_new_approach_is_easier_to_test(self, test_container_with_plugins):
        """
        NEW APPROACH: Easy to test with mocks

        Benefits:
        1. No real filesystem access needed
        2. Fast execution
        3. Reproducible results
        4. Easy to set up test data
        """
        plugin_service = test_container_with_plugins.resolve(PluginService)

        # Load plugins (from in-memory filesystem)
        plugins = await plugin_service.list_all_plugins()

        assert len(plugins) == 3
        assert all(
            p.name in ["system_plugin", "disabled_plugin", "user_plugin"]
            for p in plugins
        )

    @pytest.mark.asyncio
    async def test_service_layer_abstraction(self, test_container_with_plugins):
        """
        Test service layer provides clean abstraction

        Benefits:
        1. Single responsibility (plugin management)
        2. Clean API
        3. Hides implementation details
        """
        plugin_service = test_container_with_plugins.resolve(PluginService)

        # Enable/disable operations
        success = await plugin_service.enable_plugin("disabled_plugin")
        assert success is True

        # Verify change
        plugin = await plugin_service.get_plugin_metadata("disabled_plugin")
        assert plugin.enabled is True

        # Disable again
        success = await plugin_service.disable_plugin("disabled_plugin")
        assert success is True

        plugin = await plugin_service.get_plugin_metadata("disabled_plugin")
        assert plugin.enabled is False


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
