"""
Tests for CLI Command Classes

Tests command pattern implementation for CLI commands.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from gscripts.cli.command_classes.version_command import VersionCommand
from gscripts.cli.command_classes.help_command import HelpCommand
from gscripts.cli.command_classes.base import CommandRegistry, CommandFactory
from gscripts.models.result import CommandResult


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
    return i18n


@pytest.fixture
def mock_formatter():
    """Mock OutputFormatter"""
    formatter = Mock()
    formatter.format_help_usage = Mock(return_value="Help text")
    formatter.format_plugin_list = Mock(return_value="Plugin list")
    formatter.format_plugin_info = Mock(return_value="Plugin info")
    return formatter


@pytest.fixture
def mock_constants():
    """Mock GlobalConstants"""
    constants = Mock()
    constants.project_name = "Global Scripts"
    constants.project_version = "5.0.0"
    return constants


class TestVersionCommand:
    """Tests for VersionCommand"""

    def test_version_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test version command name property"""
        # Arrange
        command = VersionCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        name = command.name

        # Assert
        assert name == "version"

    def test_version_command_has_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test version command aliases"""
        # Arrange
        command = VersionCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        aliases = command.aliases

        # Assert
        assert "--version" in aliases
        assert "-v" in aliases
        assert "版本" in aliases

    @pytest.mark.asyncio
    async def test_version_command_execute_returns_version(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test version command execution returns version info"""
        # Arrange
        command = VersionCommand(
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
        assert result.success is True
        assert "Global Scripts" in result.output
        assert "5.0.0" in result.output


class TestHelpCommand:
    """Tests for HelpCommand"""

    def test_help_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test help command name property"""
        # Arrange
        command = HelpCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        name = command.name

        # Assert
        assert name == "help"

    def test_help_command_has_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test help command aliases"""
        # Arrange
        command = HelpCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        aliases = command.aliases

        # Assert
        assert "--help" in aliases
        assert "-h" in aliases
        assert "帮助" in aliases

    @pytest.mark.asyncio
    async def test_help_command_execute_returns_help_text(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test help command execution returns help text"""
        # Arrange
        command = HelpCommand(
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
        assert result.success is True
        assert result.output == "Help text"
        mock_formatter.format_help_usage.assert_called_once()


class TestCommandRegistry:
    """Tests for CommandRegistry"""

    def test_command_registry_initialization(self):
        """Test registry initialization"""
        # Act
        registry = CommandRegistry()

        # Assert
        assert registry is not None
        assert len(registry.list_commands()) == 0

    def test_register_command_adds_to_registry(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test registering a command"""
        # Arrange
        registry = CommandRegistry()
        command = VersionCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        registry.register(command)

        # Assert
        assert "version" in registry.list_commands()

    def test_register_command_includes_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test registering command includes aliases"""
        # Arrange
        registry = CommandRegistry()
        command = VersionCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Act
        registry.register(command)

        # Assert
        all_names = registry.list_all_names()
        assert "--version" in all_names
        assert "-v" in all_names

    def test_get_command_by_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test retrieving command by name"""
        # Arrange
        registry = CommandRegistry()
        command = VersionCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )
        registry.register(command)

        # Act
        retrieved = registry.get("version")

        # Assert
        assert retrieved is command

    def test_get_command_by_alias(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test retrieving command by alias"""
        # Arrange
        registry = CommandRegistry()
        command = VersionCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )
        registry.register(command)

        # Act
        retrieved = registry.get("--version")

        # Assert
        assert retrieved is command

    def test_get_nonexistent_command_returns_none(self):
        """Test retrieving nonexistent command returns None"""
        # Arrange
        registry = CommandRegistry()

        # Act
        result = registry.get("nonexistent")

        # Assert
        assert result is None


class TestCommandFactory:
    """Tests for CommandFactory"""

    def test_command_factory_initialization(
        self, mock_config_manager, mock_plugin_service, mock_plugin_executor
    ):
        """Test factory initialization"""
        # Act
        factory = CommandFactory(
            mock_config_manager, mock_plugin_service, mock_plugin_executor
        )

        # Assert
        assert factory is not None
        assert factory.config_manager is mock_config_manager
        assert factory.plugin_service is mock_plugin_service
        assert factory.plugin_executor is mock_plugin_executor

    def test_create_version_command(
        self, mock_config_manager, mock_plugin_service, mock_plugin_executor
    ):
        """Test creating version command"""
        # Arrange
        factory = CommandFactory(
            mock_config_manager, mock_plugin_service, mock_plugin_executor
        )

        # Act
        command = factory.create("version")

        # Assert
        assert command is not None
        assert isinstance(command, VersionCommand)
        assert command.name == "version"

    def test_create_help_command(
        self, mock_config_manager, mock_plugin_service, mock_plugin_executor
    ):
        """Test creating help command"""
        # Arrange
        factory = CommandFactory(
            mock_config_manager, mock_plugin_service, mock_plugin_executor
        )

        # Act
        command = factory.create("help")

        # Assert
        assert command is not None
        assert isinstance(command, HelpCommand)
        assert command.name == "help"

    def test_create_nonexistent_command_raises_error(
        self, mock_config_manager, mock_plugin_service, mock_plugin_executor
    ):
        """Test creating nonexistent command raises ValueError"""
        # Arrange
        factory = CommandFactory(
            mock_config_manager, mock_plugin_service, mock_plugin_executor
        )

        # Act & Assert
        with pytest.raises(ValueError):
            factory.create("nonexistent")
