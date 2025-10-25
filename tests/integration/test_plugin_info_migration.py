"""
Integration Test for Plugin Info Command V2
Tests the plugin info command using the new DI-based approach
"""

import pytest
from pathlib import Path

from src.gscripts.infrastructure import DIContainer, configure_services
from src.gscripts.infrastructure.filesystem import InMemoryFileSystem
from src.gscripts.application.services import PluginService
from src.gscripts.domain.interfaces import IFileSystem
from src.gscripts.cli.command_classes.plugin_info_command import (
    PluginInfoCommand,
    create_plugin_info_command
)


@pytest.fixture
def test_container_with_plugin():
    """Create test container with a mock plugin"""
    container = DIContainer()
    plugins_dir = Path("/test/plugins")
    config_path = Path("/test/gs.json")

    configure_services(
        container,
        use_mocks=True,
        plugins_dir=plugins_dir,
        config_path=config_path
    )

    # Setup mock plugin
    fs = container.resolve(IFileSystem)

    # Plugin with full metadata
    fs.write_json(plugins_dir / "test_plugin" / "plugin.json", {
        "name": "test_plugin",
        "version": "1.5.0",
        "author": "Test Author",
        "description": {"zh": "测试插件", "en": "Test Plugin"},
        "enabled": True,
        "priority": 20,
        "category": "testing",
        "homepage": "https://example.com",
        "license": "MIT",
        "keywords": ["test", "example"]
    })

    return container


class TestPluginInfoCommand:
    """Integration tests for plugin info command"""

    @pytest.mark.asyncio
    async def test_command_shows_plugin_info(
        self,
        test_container_with_plugin
    ):
        """Test that command correctly shows plugin information"""
        plugin_service = test_container_with_plugin.resolve(PluginService)

        # Create mock formatter and i18n
        class MockFormatter:
            def __init__(self):
                self.displayed_info = None

            def print_plugin_info(self, plugin_info):
                self.displayed_info = plugin_info

        class MockI18n:
            def get_message(self, key):
                messages = {
                    "commands.plugin_info": "Plugin info displayed",
                    "errors.missing_plugin_name": "Missing plugin name",
                    "errors.plugin_not_found": "Plugin not found",
                    "plugin_source_types.system": "System",
                }
                return messages.get(key, key)

        class MockConstants:
            exit_general_error = 1
            exit_misuse = 2
            exit_plugin_not_found = 3

        formatter = MockFormatter()
        i18n = MockI18n()
        constants = MockConstants()

        command = PluginInfoCommand(
            plugin_service=plugin_service,
            formatter=formatter,
            i18n=i18n,
            constants=constants,
            chinese=True
        )

        # Execute command
        result = await command.execute(['test_plugin'])

        # Verify result
        assert result.success is True
        assert formatter.displayed_info is not None

        # Verify displayed plugin info
        info = formatter.displayed_info
        assert info['name'] == 'test_plugin'
        assert info['version'] == '1.5.0'
        assert info['author'] == 'Test Author'
        assert '测试插件' in info['description']
        assert info['enabled'] is True
        assert info['priority'] == 20
        assert info['category'] == 'testing'
        assert info['homepage'] == 'https://example.com'
        assert info['license'] == 'MIT'
        assert 'test' in info['keywords']

    @pytest.mark.asyncio
    async def test_command_handles_missing_plugin_name(
        self,
        test_container_with_plugin
    ):
        """Test command with no plugin name argument"""
        plugin_service = test_container_with_plugin.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return "Missing plugin name" if "missing" in key else key

        class MockConstants:
            exit_general_error = 1
            exit_misuse = 2
            exit_plugin_not_found = 3

        command = PluginInfoCommand(
            plugin_service=plugin_service,
            i18n=MockI18n(),
            constants=MockConstants(),
            chinese=True
        )

        result = await command.execute([])

        assert result.success is False
        assert "Missing plugin name" in result.error
        assert result.exit_code == 2

    @pytest.mark.asyncio
    async def test_command_handles_non_existent_plugin(
        self,
        test_container_with_plugin
    ):
        """Test command with non-existent plugin"""
        plugin_service = test_container_with_plugin.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return "Plugin not found" if "not_found" in key else key

        class MockConstants:
            exit_general_error = 1
            exit_misuse = 2
            exit_plugin_not_found = 3

        command = PluginInfoCommand(
            plugin_service=plugin_service,
            i18n=MockI18n(),
            constants=MockConstants(),
            chinese=True
        )

        result = await command.execute(['non_existent'])

        assert result.success is False
        assert "Plugin not found" in result.error
        assert result.exit_code == 3

    @pytest.mark.asyncio
    async def test_factory_function_creates_command(
        self,
        test_container_with_plugin
    ):
        """Test factory function for creating command"""
        plugin_service = test_container_with_plugin.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return key

        command = create_plugin_info_command(
            plugin_service=plugin_service,
            i18n=MockI18n(),
            chinese=True
        )

        assert isinstance(command, PluginInfoCommand)
        assert command.plugin_service is plugin_service

    @pytest.mark.asyncio
    async def test_metadata_to_display_conversion(
        self,
        test_container_with_plugin
    ):
        """Test conversion from metadata to display info"""
        plugin_service = test_container_with_plugin.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return "System" if "system" in key else key

        class MockFormatter:
            def print_plugin_info(self, plugin_info):
                self.displayed_info = plugin_info

        formatter = MockFormatter()
        command = PluginInfoCommand(
            plugin_service=plugin_service,
            formatter=formatter,
            i18n=MockI18n(),
            chinese=True
        )

        await command.execute(['test_plugin'])

        # Check that metadata was properly converted
        info = formatter.displayed_info
        assert info['name'] == 'test_plugin'
        assert info['version'] == '1.5.0'
        assert info['priority'] == 20
        assert '测试插件' in info['description']

    @pytest.mark.asyncio
    async def test_localized_description_english(
        self,
        test_container_with_plugin
    ):
        """Test English localization of description"""
        plugin_service = test_container_with_plugin.resolve(PluginService)

        class MockI18n:
            def get_message(self, key):
                return key

        class MockFormatter:
            def print_plugin_info(self, plugin_info):
                self.displayed_info = plugin_info

        formatter = MockFormatter()
        command = PluginInfoCommand(
            plugin_service=plugin_service,
            formatter=formatter,
            i18n=MockI18n(),
            chinese=False  # English mode
        )

        await command.execute(['test_plugin'])

        # Should use English description
        info = formatter.displayed_info
        assert 'Test Plugin' in info['description']


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
