"""
Integration tests for CLI command flow

Tests end-to-end CLI command execution including plugin list, info,
enable/disable, status, and doctor commands.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from gscripts.cli.commands import CommandHandler
from gscripts.cli.command_classes.plugin_list_command import PluginListCommand
from gscripts.cli.command_classes.plugin_info_command import PluginInfoCommand
from gscripts.cli.command_classes.plugin_enable_command import PluginEnableCommand
from gscripts.cli.command_classes.plugin_disable_command import PluginDisableCommand
from gscripts.cli.command_classes.status_command import StatusCommand
from gscripts.models.result import CommandResult
from tests.factories.plugin_factory import PluginFactory


@pytest.mark.integration
class TestPluginListCommandFlow:
    """Integration tests for 'gs plugin list' command flow"""

    @pytest.mark.asyncio
    async def test_plugin_list_shows_all_plugins(self):
        """Test that plugin list command shows all loaded plugins"""
        # Arrange: Mock plugin service with test plugins
        mock_plugin_service = Mock()
        mock_plugin_service.get_loaded_plugins = Mock(
            return_value={
                "android": PluginFactory.create(name="android", enabled=True),
                "system": PluginFactory.create(name="system", enabled=True),
                "grep": PluginFactory.create(name="grep", enabled=False),
            }
        )

        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="Plugins")
        mock_constants = Mock()

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = PluginListCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        mock_plugin_service.get_loaded_plugins.assert_called_once()

    @pytest.mark.asyncio
    async def test_plugin_list_with_no_plugins(self):
        """Test plugin list when no plugins are loaded"""
        # Arrange
        mock_plugin_service = Mock()
        mock_plugin_service.get_loaded_plugins = Mock(return_value={})

        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="No plugins")
        mock_constants = Mock()

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = PluginListCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True


@pytest.mark.integration
class TestPluginInfoCommandFlow:
    """Integration tests for 'gs plugin info' command flow"""

    @pytest.mark.asyncio
    async def test_plugin_info_shows_plugin_details(self):
        """Test that plugin info command shows plugin details"""
        # Arrange
        test_plugin = PluginFactory.create(
            name="android",
            enabled=True,
            version="1.0.0",
            description={"zh": "Android工具", "en": "Android tools"},
        )

        mock_plugin_service = Mock()
        mock_plugin_service.get_plugin_info = AsyncMock(return_value=test_plugin)

        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="Plugin Info")
        mock_constants = Mock()

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = PluginInfoCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute(["android"])

        # Assert
        assert result.success is True
        mock_plugin_service.get_plugin_info.assert_called_once_with("android")

    @pytest.mark.asyncio
    async def test_plugin_info_without_args_shows_usage(self):
        """Test plugin info without arguments shows usage"""
        # Arrange
        mock_plugin_service = Mock()
        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="Usage")
        mock_constants = Mock()
        mock_constants.exit_invalid_arguments = 2

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = PluginInfoCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert result.exit_code == 2


@pytest.mark.integration
class TestPluginEnableDisableFlow:
    """Integration tests for plugin enable/disable command flow"""

    @pytest.mark.asyncio
    async def test_plugin_enable_success(self):
        """Test enabling a plugin"""
        # Arrange
        mock_plugin_service = Mock()
        mock_plugin_service.enable_plugin = AsyncMock(
            return_value=CommandResult(success=True, message="Enabled")
        )

        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="Enabled")
        mock_constants = Mock()

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = PluginEnableCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute(["android"])

        # Assert
        assert result.success is True
        mock_plugin_service.enable_plugin.assert_called_once_with("android")

    @pytest.mark.asyncio
    async def test_plugin_disable_success(self):
        """Test disabling a plugin"""
        # Arrange
        mock_plugin_service = Mock()
        mock_plugin_service.disable_plugin = AsyncMock(
            return_value=CommandResult(success=True, message="Disabled")
        )

        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="Disabled")
        mock_constants = Mock()

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = PluginDisableCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute(["android"])

        # Assert
        assert result.success is True
        mock_plugin_service.disable_plugin.assert_called_once_with("android")


@pytest.mark.integration
class TestStatusCommandFlow:
    """Integration tests for 'gs status' command flow"""

    @pytest.mark.asyncio
    async def test_status_command_shows_system_status(self):
        """Test that status command shows system status"""
        # Arrange
        mock_plugin_service = Mock()
        mock_plugin_service.health_check = AsyncMock(
            return_value={
                "status": "healthy",
                "plugins_total": 10,
                "plugins_enabled": 8,
                "plugins_disabled": 2,
                "functions_total": 50,
                "issues": [],
            }
        )

        mock_formatter = Mock()
        mock_i18n = Mock()
        mock_i18n.get_message = Mock(return_value="System Status")
        mock_constants = Mock()

        mock_config_manager = Mock()
        mock_plugin_executor = Mock()

        command = StatusCommand(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            i18n=mock_i18n,
            formatter=mock_formatter,
            constants=mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        mock_plugin_service.health_check.assert_called_once()


@pytest.mark.integration
class TestCommandHandlerRouting:
    """Integration tests for CommandHandler routing logic"""

    @pytest.mark.asyncio
    async def test_command_handler_routes_to_system_command(self):
        """Test CommandHandler routes system commands correctly"""
        # Arrange
        mock_config_manager = Mock()
        mock_plugin_service = Mock()
        mock_plugin_executor = Mock()

        handler = CommandHandler(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            chinese=False,
        )

        with patch.object(
            handler,
            "_execute_system_command",
            return_value=CommandResult(success=True, output="Version: 5.0.0"),
        ) as mock_execute:
            # Act
            result = await handler.handle_command(["version"])

        # Assert
        assert result.success is True
        mock_execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_command_handler_routes_plugin_subcommand(self):
        """Test CommandHandler routes plugin subcommands correctly"""
        # Arrange
        mock_config_manager = Mock()
        mock_plugin_service = Mock()
        mock_plugin_executor = Mock()

        handler = CommandHandler(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            chinese=False,
        )

        with patch.object(
            handler,
            "_handle_plugin_subcommand",
            return_value=CommandResult(success=True, output="Plugin list"),
        ) as mock_handle:
            # Act
            result = await handler.handle_command(["plugin", "list"])

        # Assert
        assert result.success is True
        mock_handle.assert_called_once_with(["list"])

    @pytest.mark.asyncio
    async def test_command_handler_shows_help_for_empty_args(self):
        """Test CommandHandler shows help for empty arguments"""
        # Arrange
        mock_config_manager = Mock()
        mock_plugin_service = Mock()
        mock_plugin_executor = Mock()

        handler = CommandHandler(
            config_manager=mock_config_manager,
            plugin_service=mock_plugin_service,
            plugin_executor=mock_plugin_executor,
            chinese=False,
        )

        with patch.object(
            handler,
            "_execute_system_command",
            return_value=CommandResult(success=True, output="Help"),
        ) as mock_execute:
            # Act
            result = await handler.handle_command([])

        # Assert
        assert result.success is True
        mock_execute.assert_called_once_with("help", [])
