"""
Tests for CommandHandler

Tests command routing and delegation logic.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch

from gscripts.cli.commands import CommandHandler
from gscripts.models.result import CommandResult


# Fixtures for CommandHandler dependencies
@pytest.fixture
def mock_config_manager():
    """Mock ConfigManager"""
    manager = Mock()
    manager.get.return_value = "test_value"
    return manager


@pytest.fixture
def mock_plugin_service():
    """Mock PluginService"""
    service = Mock()
    service.get_loaded_plugins = Mock(return_value={})
    return service


@pytest.fixture
def mock_plugin_executor():
    """Mock PluginExecutor"""
    executor = Mock()
    executor.execute_plugin_function = AsyncMock(
        return_value=CommandResult(success=True, output="test output")
    )
    return executor


@pytest.fixture
def mock_command_registry():
    """Mock CommandRegistry"""
    registry = Mock()
    registry.has_command = Mock(return_value=False)
    registry.get = Mock(return_value=None)
    registry.list_commands = Mock(return_value=[])
    return registry


@pytest.fixture
def command_handler(mock_config_manager, mock_plugin_service, mock_plugin_executor):
    """CommandHandler instance with mocked dependencies"""
    return CommandHandler(
        mock_config_manager, mock_plugin_service, mock_plugin_executor, chinese=True
    )


class TestCommandHandlerInitialization:
    """Tests for CommandHandler initialization"""

    def test_command_handler_initialization(
        self, mock_config_manager, mock_plugin_service, mock_plugin_executor
    ):
        """Test CommandHandler initialization"""
        # Act
        handler = CommandHandler(
            mock_config_manager, mock_plugin_service, mock_plugin_executor, chinese=True
        )

        # Assert
        assert handler.config_manager is mock_config_manager
        assert handler.plugin_service is mock_plugin_service
        assert handler.plugin_executor is mock_plugin_executor
        assert handler.chinese is True
        assert handler.formatter is not None
        assert handler.constants is not None
        assert handler.i18n is not None
        assert handler.command_registry is not None


class TestCommandRouting:
    """Tests for command routing logic"""

    @pytest.mark.asyncio
    async def test_handle_command_with_empty_args_shows_help(self, command_handler):
        """Test handle_command with empty args routes to help"""
        # Arrange
        mock_help_result = CommandResult(success=True, output="Help text")

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_help_result
        ) as mock_execute:
            # Act
            result = await command_handler.handle_command([])

        # Assert
        assert result.success is True
        assert result.output == "Help text"
        mock_execute.assert_called_once_with("help", [])

    @pytest.mark.asyncio
    async def test_handle_command_routes_system_command(self, command_handler):
        """Test handle_command routes to system command"""
        # Arrange
        mock_version_result = CommandResult(success=True, output="v5.0.0")

        with patch.object(
            command_handler, "_is_system_command", return_value=True
        ), patch.object(
            command_handler, "_execute_system_command", return_value=mock_version_result
        ) as mock_execute:
            # Act
            result = await command_handler.handle_command(["version"])

        # Assert
        assert result.success is True
        assert result.output == "v5.0.0"
        mock_execute.assert_called_once_with("version", [])

    @pytest.mark.asyncio
    async def test_handle_command_routes_plugin_subcommand(self, command_handler):
        """Test handle_command routes 'plugin' to plugin subcommand handler"""
        # Arrange
        mock_plugin_result = CommandResult(success=True, output="Plugin list")

        with patch.object(
            command_handler, "_is_system_command", return_value=False
        ), patch.object(
            command_handler,
            "_handle_plugin_subcommand",
            return_value=mock_plugin_result,
        ) as mock_handle:
            # Act
            result = await command_handler.handle_command(["plugin", "list"])

        # Assert
        assert result.success is True
        assert result.output == "Plugin list"
        mock_handle.assert_called_once_with(["list"])

    @pytest.mark.asyncio
    async def test_handle_command_routes_plugin_function(self, command_handler):
        """Test handle_command routes to plugin function execution"""
        # Arrange
        mock_plugin_result = CommandResult(success=True, output="Function result")

        with patch.object(
            command_handler, "_is_system_command", return_value=False
        ), patch.object(
            command_handler,
            "_try_execute_plugin_function",
            return_value=mock_plugin_result,
        ) as mock_try_exec:
            # Act
            result = await command_handler.handle_command(["android", "devices"])

        # Assert
        assert result.success is True
        assert result.output == "Function result"
        mock_try_exec.assert_called_once_with(["android", "devices"])

    @pytest.mark.asyncio
    async def test_handle_command_routes_single_command(self, command_handler):
        """Test handle_command routes single command to handler"""
        # Arrange
        mock_single_result = CommandResult(success=True, output="Plugin info")

        with patch.object(
            command_handler, "_is_system_command", return_value=False
        ), patch.object(
            command_handler, "_try_execute_plugin_function", return_value=None
        ), patch.object(
            command_handler, "_handle_single_command", return_value=mock_single_result
        ) as mock_handle:
            # Act
            result = await command_handler.handle_command(["android"])

        # Assert
        assert result.success is True
        assert result.output == "Plugin info"
        mock_handle.assert_called_once_with("android")


class TestSystemCommandExecution:
    """Tests for system command execution"""

    def test_is_system_command_returns_true_for_registered_command(
        self, command_handler
    ):
        """Test _is_system_command returns True for registered command"""
        # Arrange
        command_handler.command_registry.has_command = Mock(return_value=True)

        # Act
        result = command_handler._is_system_command("help")

        # Assert
        assert result is True
        command_handler.command_registry.has_command.assert_called_once_with("help")

    def test_is_system_command_returns_false_for_unregistered_command(
        self, command_handler
    ):
        """Test _is_system_command returns False for unregistered command"""
        # Arrange
        command_handler.command_registry.has_command = Mock(return_value=False)

        # Act
        result = command_handler._is_system_command("unknown")

        # Assert
        assert result is False
        command_handler.command_registry.has_command.assert_called_once_with("unknown")

    @pytest.mark.asyncio
    async def test_execute_system_command_success(self, command_handler):
        """Test _execute_system_command executes command"""
        # Arrange
        mock_command = Mock()
        mock_command.execute = AsyncMock(
            return_value=CommandResult(success=True, output="Command output")
        )
        command_handler.command_registry.get = Mock(return_value=mock_command)

        # Act
        result = await command_handler._execute_system_command("help", [])

        # Assert
        assert result.success is True
        assert result.output == "Command output"
        mock_command.execute.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_execute_system_command_not_found(self, command_handler):
        """Test _execute_system_command handles command not found"""
        # Arrange
        command_handler.command_registry.get = Mock(return_value=None)

        # Act
        result = await command_handler._execute_system_command("unknown", [])

        # Assert
        assert result.success is False
        assert "Unknown command" in result.error
        assert result.exit_code == command_handler.constants.exit_command_not_found


class TestPluginSubcommandHandling:
    """Tests for plugin subcommand handling"""

    @pytest.mark.asyncio
    async def test_handle_plugin_subcommand_without_args_defaults_to_list(
        self, command_handler
    ):
        """Test _handle_plugin_subcommand without args defaults to list"""
        # Arrange
        mock_list_result = CommandResult(success=True, output="Plugin list")

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_list_result
        ) as mock_execute:
            # Act
            result = await command_handler._handle_plugin_subcommand([])

        # Assert
        assert result.success is True
        assert result.output == "Plugin list"
        mock_execute.assert_called_once_with("plugin:list", [])

    @pytest.mark.asyncio
    async def test_handle_plugin_subcommand_routes_list(self, command_handler):
        """Test _handle_plugin_subcommand routes 'list' to plugin:list"""
        # Arrange
        mock_list_result = CommandResult(success=True, output="Plugin list")
        command_handler.command_registry.has_command = Mock(return_value=True)

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_list_result
        ) as mock_execute:
            # Act
            result = await command_handler._handle_plugin_subcommand(["list"])

        # Assert
        assert result.success is True
        mock_execute.assert_called_once_with("plugin:list", [])

    @pytest.mark.asyncio
    async def test_handle_plugin_subcommand_routes_info(self, command_handler):
        """Test _handle_plugin_subcommand routes 'info' to plugin:info"""
        # Arrange
        mock_info_result = CommandResult(success=True, output="Plugin info")
        command_handler.command_registry.has_command = Mock(return_value=True)

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_info_result
        ) as mock_execute:
            # Act
            result = await command_handler._handle_plugin_subcommand(
                ["info", "android"]
            )

        # Assert
        assert result.success is True
        mock_execute.assert_called_once_with("plugin:info", ["android"])

    @pytest.mark.asyncio
    async def test_handle_plugin_subcommand_routes_enable(self, command_handler):
        """Test _handle_plugin_subcommand routes 'enable' to plugin:enable"""
        # Arrange
        mock_enable_result = CommandResult(success=True, output="Plugin enabled")
        command_handler.command_registry.has_command = Mock(return_value=True)

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_enable_result
        ) as mock_execute:
            # Act
            result = await command_handler._handle_plugin_subcommand(
                ["enable", "android"]
            )

        # Assert
        assert result.success is True
        mock_execute.assert_called_once_with("plugin:enable", ["android"])

    @pytest.mark.asyncio
    async def test_handle_plugin_subcommand_routes_disable(self, command_handler):
        """Test _handle_plugin_subcommand routes 'disable' to plugin:disable"""
        # Arrange
        mock_disable_result = CommandResult(success=True, output="Plugin disabled")
        command_handler.command_registry.has_command = Mock(return_value=True)

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_disable_result
        ) as mock_execute:
            # Act
            result = await command_handler._handle_plugin_subcommand(
                ["disable", "android"]
            )

        # Assert
        assert result.success is True
        mock_execute.assert_called_once_with("plugin:disable", ["android"])

    @pytest.mark.asyncio
    async def test_handle_plugin_subcommand_unknown_subcommand(self, command_handler):
        """Test _handle_plugin_subcommand handles unknown subcommand"""
        # Act
        result = await command_handler._handle_plugin_subcommand(["unknown"])

        # Assert
        assert result.success is False
        assert result.exit_code == command_handler.constants.exit_command_not_found


class TestPluginFunctionExecution:
    """Tests for plugin function execution"""

    @pytest.mark.asyncio
    async def test_try_execute_plugin_function_two_layer(self, command_handler):
        """Test _try_execute_plugin_function with 2-layer command"""
        # Arrange
        mock_plugin_result = CommandResult(success=True, output="Function result")
        command_handler.plugin_service.get_loaded_plugins = Mock(
            return_value={"android": {"functions": {"devices": {}}}}
        )

        with patch.object(
            command_handler,
            "_execute_plugin_function",
            return_value=mock_plugin_result,
        ) as mock_exec:
            # Act
            result = await command_handler._try_execute_plugin_function(
                ["android", "devices"]
            )

        # Assert
        assert result.success is True
        assert result.output == "Function result"
        mock_exec.assert_called_once_with("android", "devices", [])

    @pytest.mark.asyncio
    async def test_try_execute_plugin_function_three_layer_composite(
        self, command_handler
    ):
        """Test _try_execute_plugin_function with 3-layer composite function"""
        # Arrange
        mock_plugin_result = CommandResult(success=True, output="Composite result")
        command_handler.plugin_service.get_loaded_plugins = Mock(
            return_value={
                "system": {"functions": {"cpu info": {}}}  # composite function name
            }
        )

        with patch.object(
            command_handler,
            "_execute_plugin_function",
            return_value=mock_plugin_result,
        ) as mock_exec:
            # Act
            result = await command_handler._try_execute_plugin_function(
                ["system", "cpu", "info"]
            )

        # Assert
        assert result.success is True
        assert result.output == "Composite result"
        mock_exec.assert_called_once_with("system", "cpu info", [])

    @pytest.mark.asyncio
    async def test_try_execute_plugin_function_three_layer_fallback(
        self, command_handler
    ):
        """Test _try_execute_plugin_function with 3-layer fallback"""
        # Arrange
        mock_plugin_result = CommandResult(success=True, output="Fallback result")
        command_handler.plugin_service.get_loaded_plugins = Mock(
            return_value={"system": {"functions": {"cpu": {}}}}  # cpu is the function
        )

        with patch.object(
            command_handler,
            "_execute_plugin_function",
            return_value=mock_plugin_result,
        ) as mock_exec:
            # Act
            result = await command_handler._try_execute_plugin_function(
                ["system", "cpu", "arg1"]
            )

        # Assert
        assert result.success is True
        assert result.output == "Fallback result"
        mock_exec.assert_called_once_with("system", "cpu", ["arg1"])

    @pytest.mark.asyncio
    async def test_try_execute_plugin_function_plugin_not_loaded(self, command_handler):
        """Test _try_execute_plugin_function when plugin not loaded"""
        # Arrange
        command_handler.plugin_service.get_loaded_plugins = Mock(return_value={})

        # Act
        result = await command_handler._try_execute_plugin_function(
            ["nonexistent", "function"]
        )

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_execute_plugin_function_delegates_to_executor(self, command_handler):
        """Test _execute_plugin_function delegates to PluginExecutor"""
        # Arrange
        mock_result = CommandResult(success=True, output="Executor result")
        command_handler.plugin_executor.execute_plugin_function = AsyncMock(
            return_value=mock_result
        )

        # Act
        result = await command_handler._execute_plugin_function(
            "android", "devices", ["arg1"]
        )

        # Assert
        assert result.success is True
        assert result.output == "Executor result"
        command_handler.plugin_executor.execute_plugin_function.assert_called_once_with(
            "android", "devices", ["arg1"]
        )


class TestSingleCommandHandling:
    """Tests for single command handling"""

    @pytest.mark.asyncio
    async def test_handle_single_command_for_loaded_plugin(self, command_handler):
        """Test _handle_single_command for loaded plugin shows info"""
        # Arrange
        mock_info_result = CommandResult(success=True, output="Plugin info")
        command_handler.plugin_service.get_loaded_plugins = Mock(
            return_value={"android": {}}
        )

        with patch.object(
            command_handler, "_execute_system_command", return_value=mock_info_result
        ) as mock_execute:
            # Act
            result = await command_handler._handle_single_command("android")

        # Assert
        assert result.success is True
        assert result.output == "Plugin info"
        mock_execute.assert_called_once_with("plugin:info", ["android"])

    @pytest.mark.asyncio
    async def test_handle_single_command_for_unknown_command(self, command_handler):
        """Test _handle_single_command for unknown command"""
        # Arrange
        command_handler.plugin_service.get_loaded_plugins = Mock(return_value={})

        # Act
        result = await command_handler._handle_single_command("unknown")

        # Assert
        assert result.success is False
        assert result.exit_code == command_handler.constants.exit_command_not_found
