"""
Tests for CLI Plugin Commands

Tests command pattern implementation for plugin-related CLI commands.
"""

import pytest
from unittest.mock import Mock, AsyncMock
from pathlib import Path

from gscripts.cli.command_classes.status_command import StatusCommand
from gscripts.cli.command_classes.plugin_list_command import PluginListCommand
from gscripts.cli.command_classes.plugin_info_command import PluginInfoCommand
from gscripts.cli.command_classes.plugin_enable_command import PluginEnableCommand
from gscripts.cli.command_classes.plugin_disable_command import PluginDisableCommand
from gscripts.models.result import CommandResult
from gscripts.models.plugin import PluginMetadata


# Fixtures for command dependencies
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
    service.get_all_plugins = AsyncMock(return_value=[])
    service.get_plugin_metadata = AsyncMock(return_value=None)
    service.list_all_plugins = AsyncMock(return_value=[])
    service.enable_plugin = AsyncMock(return_value=True)
    service.disable_plugin = AsyncMock(return_value=True)
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
def mock_i18n():
    """Mock I18nManager"""
    i18n = Mock()
    i18n.get_message = Mock(side_effect=lambda key, **kwargs: f"i18n:{key}")
    i18n.current_language = "zh"
    return i18n


@pytest.fixture
def mock_formatter():
    """Mock OutputFormatter"""
    formatter = Mock()
    formatter.format_help_usage = Mock(return_value="Help text")
    formatter.format_plugin_list = Mock(return_value="Plugin list")
    formatter.print_plugin_list = Mock()
    formatter.print_plugin_info = Mock()
    return formatter


@pytest.fixture
def mock_constants():
    """Mock GlobalConstants"""
    constants = Mock()
    constants.project_name = "Global Scripts"
    constants.project_version = "5.0.0"
    constants.exit_execution_error = 1
    constants.exit_general_error = 1
    constants.exit_misuse = 2
    constants.exit_plugin_not_found = 10
    constants.exit_invalid_arguments = 2
    constants.gs_home = Path("/fake/gs_home")
    return constants


@pytest.fixture
def sample_plugin_metadata():
    """Sample plugin metadata for testing"""
    return PluginMetadata(
        name="test_plugin",
        version="1.0.0",
        author="Test Author",
        description={"zh": "测试插件", "en": "Test plugin"},
        enabled=True,
        priority=50,
        homepage="https://example.com",
        license="MIT",
        category="testing",
        keywords=["test", "example"],
    )


class TestStatusCommand:
    """Tests for StatusCommand"""

    def test_status_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test status command name property"""
        # Arrange & Act
        command = StatusCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "status"

    def test_status_command_has_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test status command aliases"""
        # Arrange & Act
        command = StatusCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert "状态" in command.aliases

    @pytest.mark.asyncio
    async def test_status_command_execute_success(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test status command execution success"""
        # Arrange
        command = StatusCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Mock system_commands.system_status
        mock_system_status = AsyncMock(
            return_value=CommandResult(success=True, output="System OK")
        )
        command.system_commands.system_status = mock_system_status

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        assert result.output == "System OK"
        mock_system_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_status_command_execute_handles_exception(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test status command handles exceptions"""
        # Arrange
        command = StatusCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Mock system_commands.system_status to raise exception
        mock_system_status = AsyncMock(side_effect=RuntimeError("System error"))
        command.system_commands.system_status = mock_system_status

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert "System error" in result.error
        assert result.exit_code == mock_constants.exit_execution_error


class TestPluginListCommand:
    """Tests for PluginListCommand"""

    def test_plugin_list_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin list command name property"""
        # Arrange & Act
        command = PluginListCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "plugin:list"

    def test_plugin_list_command_has_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin list command aliases"""
        # Arrange & Act
        command = PluginListCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert "plugins" in command.aliases

    @pytest.mark.asyncio
    async def test_plugin_list_command_execute_with_no_plugins(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin list execution with no plugins"""
        # Arrange
        command = PluginListCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.list_all_plugins = AsyncMock(return_value=[])

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        assert "i18n:plugin_list.no_plugins" in result.message

    @pytest.mark.asyncio
    async def test_plugin_list_command_execute_with_plugins(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
        sample_plugin_metadata,
    ):
        """Test plugin list execution with plugins"""
        # Arrange
        command = PluginListCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.list_all_plugins = AsyncMock(
            return_value=[sample_plugin_metadata]
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        mock_formatter.print_plugin_list.assert_called_once()

    @pytest.mark.asyncio
    async def test_plugin_list_command_separates_enabled_disabled(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin list separates enabled and disabled plugins"""
        # Arrange
        command = PluginListCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        enabled_plugin = PluginMetadata(
            name="enabled_plugin",
            version="1.0.0",
            description={"zh": "启用的插件", "en": "Enabled plugin"},
            enabled=True,
        )
        disabled_plugin = PluginMetadata(
            name="disabled_plugin",
            version="1.0.0",
            description={"zh": "禁用的插件", "en": "Disabled plugin"},
            enabled=False,
        )

        mock_plugin_service.list_all_plugins = AsyncMock(
            return_value=[enabled_plugin, disabled_plugin]
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        mock_formatter.print_plugin_list.assert_called_once()

        # Get the call arguments to verify separation
        call_args = mock_formatter.print_plugin_list.call_args
        enabled_list = call_args[0][0]
        disabled_list = call_args[0][1]

        assert len(enabled_list) == 1
        assert len(disabled_list) == 1
        assert enabled_list[0]["name"] == "enabled_plugin"
        assert disabled_list[0]["name"] == "disabled_plugin"

    @pytest.mark.asyncio
    async def test_plugin_list_command_handles_exception(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin list command handles exceptions"""
        # Arrange
        command = PluginListCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.list_all_plugins = AsyncMock(
            side_effect=RuntimeError("Service error")
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert "Failed to list plugins" in result.error
        assert result.exit_code == mock_constants.exit_general_error


class TestPluginInfoCommand:
    """Tests for PluginInfoCommand"""

    def test_plugin_info_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin info command name property"""
        # Arrange & Act
        command = PluginInfoCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "plugin:info"

    def test_plugin_info_command_has_no_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin info command has no aliases"""
        # Arrange & Act
        command = PluginInfoCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert len(command.aliases) == 0

    @pytest.mark.asyncio
    async def test_plugin_info_command_execute_without_args(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin info execution without plugin name"""
        # Arrange
        command = PluginInfoCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert "i18n:errors.missing_plugin_name" in result.error
        assert result.exit_code == mock_constants.exit_misuse

    @pytest.mark.asyncio
    async def test_plugin_info_command_execute_with_nonexistent_plugin(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin info execution with nonexistent plugin"""
        # Arrange
        command = PluginInfoCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.get_plugin_metadata = AsyncMock(return_value=None)

        # Act
        result = await command.execute(["nonexistent_plugin"])

        # Assert
        assert result.success is False
        assert "i18n:errors.plugin_not_found" in result.error
        assert result.exit_code == mock_constants.exit_plugin_not_found

    @pytest.mark.asyncio
    async def test_plugin_info_command_execute_with_existing_plugin(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
        sample_plugin_metadata,
    ):
        """Test plugin info execution with existing plugin"""
        # Arrange
        command = PluginInfoCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.get_plugin_metadata = AsyncMock(
            return_value=sample_plugin_metadata
        )

        # Act
        result = await command.execute(["test_plugin"])

        # Assert
        assert result.success is True
        mock_formatter.print_plugin_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_plugin_info_command_handles_exception(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin info command handles exceptions"""
        # Arrange
        command = PluginInfoCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.get_plugin_metadata = AsyncMock(
            side_effect=RuntimeError("Service error")
        )

        # Act
        result = await command.execute(["test_plugin"])

        # Assert
        assert result.success is False
        assert "Failed to get plugin info" in result.error
        assert result.exit_code == mock_constants.exit_general_error


class TestPluginEnableCommand:
    """Tests for PluginEnableCommand"""

    def test_plugin_enable_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin enable command name property"""
        # Arrange & Act
        command = PluginEnableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "plugin:enable"

    def test_plugin_enable_command_has_no_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin enable command has no aliases"""
        # Arrange & Act
        command = PluginEnableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert len(command.aliases) == 0

    @pytest.mark.asyncio
    async def test_plugin_enable_command_execute_without_args(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin enable execution without plugin name"""
        # Arrange
        command = PluginEnableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert "i18n:errors.plugin_name_required" in result.error
        assert result.exit_code == mock_constants.exit_invalid_arguments

    @pytest.mark.asyncio
    async def test_plugin_enable_command_execute_success(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin enable execution success"""
        # Arrange
        command = PluginEnableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.enable_plugin = AsyncMock(return_value=True)

        # Act
        result = await command.execute(["test_plugin"])

        # Assert
        assert result.success is True
        assert "test_plugin" in result.output
        assert "enabled successfully" in result.output
        assert result.exit_code == 0
        mock_plugin_service.enable_plugin.assert_called_once_with("test_plugin")

    @pytest.mark.asyncio
    async def test_plugin_enable_command_execute_failure(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin enable execution failure"""
        # Arrange
        command = PluginEnableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.enable_plugin = AsyncMock(return_value=False)

        # Act
        result = await command.execute(["test_plugin"])

        # Assert
        assert result.success is False
        assert "Failed to enable plugin" in result.error
        assert "test_plugin" in result.error
        assert result.exit_code == 1


class TestPluginDisableCommand:
    """Tests for PluginDisableCommand"""

    def test_plugin_disable_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin disable command name property"""
        # Arrange & Act
        command = PluginDisableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "plugin:disable"

    def test_plugin_disable_command_has_no_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin disable command has no aliases"""
        # Arrange & Act
        command = PluginDisableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert len(command.aliases) == 0

    @pytest.mark.asyncio
    async def test_plugin_disable_command_execute_without_args(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin disable execution without plugin name"""
        # Arrange
        command = PluginDisableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert "i18n:errors.plugin_name_required" in result.error
        assert result.exit_code == mock_constants.exit_invalid_arguments

    @pytest.mark.asyncio
    async def test_plugin_disable_command_execute_success(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin disable execution success"""
        # Arrange
        command = PluginDisableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.disable_plugin = AsyncMock(return_value=True)

        # Act
        result = await command.execute(["test_plugin"])

        # Assert
        assert result.success is True
        assert "test_plugin" in result.output
        assert "disabled successfully" in result.output
        assert result.exit_code == 0
        mock_plugin_service.disable_plugin.assert_called_once_with("test_plugin")

    @pytest.mark.asyncio
    async def test_plugin_disable_command_execute_failure(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test plugin disable execution failure"""
        # Arrange
        command = PluginDisableCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_plugin_service.disable_plugin = AsyncMock(return_value=False)

        # Act
        result = await command.execute(["test_plugin"])

        # Assert
        assert result.success is False
        assert "Failed to disable plugin" in result.error
        assert "test_plugin" in result.error
        assert result.exit_code == 1
