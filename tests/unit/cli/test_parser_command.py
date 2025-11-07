"""
Tests for ParserCommand

Tests parser management command functionality.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch, mock_open
from pathlib import Path
import json

from gscripts.cli.command_classes.parser_command import ParserCommand
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
    return formatter


@pytest.fixture
def mock_constants():
    """Mock GlobalConstants"""
    constants = Mock()
    constants.project_name = "Global Scripts"
    constants.project_version = "5.0.0"
    constants.exit_execution_error = 1
    constants.exit_invalid_arguments = 2
    return constants


@pytest.fixture
def parser_command(
    mock_config_manager,
    mock_plugin_service,
    mock_plugin_executor,
    mock_i18n,
    mock_formatter,
    mock_constants,
):
    """ParserCommand instance with mocked dependencies"""
    return ParserCommand(
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    )


class TestParserCommandBasics:
    """Tests for ParserCommand basic properties"""

    def test_parser_command_name(self, parser_command):
        """Test parser command name property"""
        assert parser_command.name == "parser"

    def test_parser_command_aliases(self, parser_command):
        """Test parser command has no aliases"""
        assert parser_command.aliases == []


class TestParserCommandRouting:
    """Tests for command routing and subcommand delegation"""

    @pytest.mark.asyncio
    async def test_execute_without_args_shows_usage(self, parser_command):
        """Test execute without args shows usage"""
        # Act
        result = await parser_command.execute([])

        # Assert
        assert result.success is True
        assert "Parser Management Commands:" in result.output
        assert "list" in result.output
        assert "info" in result.output

    @pytest.mark.asyncio
    async def test_execute_with_invalid_subcommand_shows_usage(self, parser_command):
        """Test execute with invalid subcommand shows usage"""
        # Act
        result = await parser_command.execute(["invalid_subcommand"])

        # Assert
        assert result.success is True
        assert "Parser Management Commands:" in result.output

    @pytest.mark.asyncio
    async def test_execute_routes_to_list_parsers(self, parser_command):
        """Test execute routes 'list' to _list_parsers"""
        # Arrange
        with patch.object(
            parser_command,
            "_list_parsers",
            return_value=CommandResult(success=True, output="Parser list"),
        ) as mock_list:
            # Act
            result = await parser_command.execute(["list"])

        # Assert
        assert result.success is True
        assert result.output == "Parser list"
        mock_list.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_routes_to_parser_info(self, parser_command):
        """Test execute routes 'info' to _parser_info"""
        # Arrange
        with patch.object(
            parser_command,
            "_parser_info",
            return_value=CommandResult(success=True, output="Parser info"),
        ) as mock_info:
            # Act
            result = await parser_command.execute(["info", "python"])

        # Assert
        assert result.success is True
        assert result.output == "Parser info"
        mock_info.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_routes_to_enable_parser(self, parser_command):
        """Test execute routes 'enable' to _enable_parser"""
        # Arrange
        with patch.object(
            parser_command,
            "_enable_parser",
            return_value=CommandResult(success=True, output="Parser enabled"),
        ) as mock_enable:
            # Act
            result = await parser_command.execute(["enable", "python"])

        # Assert
        assert result.success is True
        assert result.output == "Parser enabled"
        mock_enable.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_routes_to_disable_parser(self, parser_command):
        """Test execute routes 'disable' to _disable_parser"""
        # Arrange
        with patch.object(
            parser_command,
            "_disable_parser",
            return_value=CommandResult(success=True, output="Parser disabled"),
        ) as mock_disable:
            # Act
            result = await parser_command.execute(["disable", "python"])

        # Assert
        assert result.success is True
        assert result.output == "Parser disabled"
        mock_disable.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_routes_to_test_parser(self, parser_command):
        """Test execute routes 'test' to _test_parser"""
        # Arrange
        with patch.object(
            parser_command,
            "_test_parser",
            return_value=CommandResult(success=True, output="Parser test result"),
        ) as mock_test:
            # Act
            result = await parser_command.execute(["test", "plugin.py"])

        # Assert
        assert result.success is True
        assert result.output == "Parser test result"
        mock_test.assert_called_once()


class TestListParsers:
    """Tests for _list_parsers subcommand"""

    @pytest.mark.asyncio
    async def test_list_parsers_with_empty_registry(self, parser_command):
        """Test list parsers with empty registry"""
        # Arrange
        mock_loader = Mock()
        mock_loader.parser_registry.list_parsers.return_value = []

        with patch.object(
            parser_command, "_load_parser_config", return_value={}
        ), patch(
            "gscripts.cli.command_classes.parser_command.RefactoredPluginLoader",
            return_value=mock_loader,
        ):
            # Act
            result = await parser_command._list_parsers([])

        # Assert
        assert result.success is True
        assert "No parsers registered" in result.output

    @pytest.mark.asyncio
    async def test_list_parsers_with_parsers(self, parser_command):
        """Test list parsers with populated registry"""
        # Arrange
        mock_parser_info = [
            {
                "name": "PythonParser",
                "priority": 100,
                "enabled": True,
                "supported_extensions": [".py"],
                "description": "Parse Python plugins",
            },
            {
                "name": "ShellParser",
                "priority": 90,
                "enabled": True,
                "supported_extensions": [".sh"],
                "description": "Parse Shell plugins",
            },
        ]

        mock_loader = Mock()
        mock_loader.parser_registry.list_parsers.return_value = mock_parser_info

        with patch.object(
            parser_command, "_load_parser_config", return_value={}
        ), patch(
            "gscripts.cli.command_classes.parser_command.RefactoredPluginLoader",
            return_value=mock_loader,
        ), patch(
            "gscripts.cli.formatters.ChineseFormatter.format_table",
            return_value="Formatted table",
        ):
            # Act
            result = await parser_command._list_parsers([])

        # Assert
        assert result.success is True
        assert "Registered Parsers" in result.output
        assert "Formatted table" in result.output

    @pytest.mark.asyncio
    async def test_list_parsers_handles_exception(self, parser_command):
        """Test list parsers handles exceptions"""
        # Arrange
        with patch.object(
            parser_command,
            "_load_parser_config",
            side_effect=RuntimeError("Config error"),
        ):
            # Act
            result = await parser_command._list_parsers([])

        # Assert
        assert result.success is False
        assert "Failed to list parsers" in result.error
        assert result.exit_code == 1


class TestParserInfo:
    """Tests for _parser_info subcommand"""

    @pytest.mark.asyncio
    async def test_parser_info_without_args(self, parser_command):
        """Test parser info without parser name"""
        # Act
        result = await parser_command._parser_info([])

        # Assert
        assert result.success is False
        assert "Usage:" in result.error
        assert result.exit_code == 2

    @pytest.mark.asyncio
    async def test_parser_info_with_nonexistent_parser(self, parser_command):
        """Test parser info with nonexistent parser"""
        # Arrange
        mock_loader = Mock()
        mock_loader.parser_registry.get_parser_info.return_value = None

        with patch.object(
            parser_command, "_load_parser_config", return_value={}
        ), patch(
            "gscripts.cli.command_classes.parser_command.RefactoredPluginLoader",
            return_value=mock_loader,
        ):
            # Act
            result = await parser_command._parser_info(["nonexistent"])

        # Assert
        assert result.success is False
        assert "not found" in result.error
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_parser_info_with_existing_parser(self, parser_command):
        """Test parser info with existing parser"""
        # Arrange
        mock_parser_info = {
            "name": "PythonParser",
            "class": "PythonFunctionParser",
            "priority": 100,
            "enabled": True,
            "version": "1.0.0",
            "supported_extensions": [".py"],
            "description": "Parse Python plugins",
        }

        mock_loader = Mock()
        mock_loader.parser_registry.get_parser_info.return_value = mock_parser_info

        with patch.object(
            parser_command, "_load_parser_config", return_value={}
        ), patch(
            "gscripts.cli.command_classes.parser_command.RefactoredPluginLoader",
            return_value=mock_loader,
        ), patch(
            "gscripts.cli.formatters.ChineseFormatter.format_info_table",
            return_value="Formatted info table",
        ):
            # Act
            result = await parser_command._parser_info(["python"])

        # Assert
        assert result.success is True
        assert "Parser Information" in result.output
        assert "Formatted info table" in result.output

    @pytest.mark.asyncio
    async def test_parser_info_handles_exception(self, parser_command):
        """Test parser info handles exceptions"""
        # Arrange
        with patch.object(
            parser_command,
            "_load_parser_config",
            side_effect=RuntimeError("Config error"),
        ):
            # Act
            result = await parser_command._parser_info(["python"])

        # Assert
        assert result.success is False
        assert "Failed to get parser info" in result.error
        assert result.exit_code == 1


class TestEnableParser:
    """Tests for _enable_parser subcommand"""

    @pytest.mark.asyncio
    async def test_enable_parser_without_args(self, parser_command):
        """Test enable parser without parser name"""
        # Act
        result = await parser_command._enable_parser([])

        # Assert
        assert result.success is False
        assert "Usage:" in result.error
        assert result.exit_code == 2

    @pytest.mark.asyncio
    async def test_enable_parser_success(self, parser_command):
        """Test enable parser success"""
        # Arrange
        mock_config = {"parsers": {"enabled": [], "disabled": ["python"]}}

        with patch.object(
            parser_command, "_get_config_path", return_value=Path("/fake/config.json")
        ), patch.object(
            parser_command, "_load_config", return_value=mock_config
        ), patch.object(
            parser_command, "_save_config"
        ) as mock_save:
            # Act
            result = await parser_command._enable_parser(["python"])

        # Assert
        assert result.success is True
        assert "enabled" in result.output
        assert "gs refresh" in result.output
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_parser_without_parsers_config(self, parser_command):
        """Test enable parser when parsers config doesn't exist"""
        # Arrange
        mock_config = {}  # No parsers key

        with patch.object(
            parser_command, "_get_config_path", return_value=Path("/fake/config.json")
        ), patch.object(
            parser_command, "_load_config", return_value=mock_config
        ), patch.object(
            parser_command, "_save_config"
        ) as mock_save:
            # Act
            result = await parser_command._enable_parser(["python"])

        # Assert
        assert result.success is True
        assert "enabled" in result.output
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_enable_parser_handles_exception(self, parser_command):
        """Test enable parser handles exceptions"""
        # Arrange
        with patch.object(
            parser_command,
            "_get_config_path",
            side_effect=RuntimeError("Config error"),
        ):
            # Act
            result = await parser_command._enable_parser(["python"])

        # Assert
        assert result.success is False
        assert "Failed to enable parser" in result.error
        assert result.exit_code == 1


class TestDisableParser:
    """Tests for _disable_parser subcommand"""

    @pytest.mark.asyncio
    async def test_disable_parser_without_args(self, parser_command):
        """Test disable parser without parser name"""
        # Act
        result = await parser_command._disable_parser([])

        # Assert
        assert result.success is False
        assert "Usage:" in result.error
        assert result.exit_code == 2

    @pytest.mark.asyncio
    async def test_disable_parser_success(self, parser_command):
        """Test disable parser success"""
        # Arrange
        mock_config = {"parsers": {"enabled": ["python"], "disabled": []}}

        with patch.object(
            parser_command, "_get_config_path", return_value=Path("/fake/config.json")
        ), patch.object(
            parser_command, "_load_config", return_value=mock_config
        ), patch.object(
            parser_command, "_save_config"
        ) as mock_save:
            # Act
            result = await parser_command._disable_parser(["python"])

        # Assert
        assert result.success is True
        assert "disabled" in result.output
        assert "gs refresh" in result.output
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_parser_without_parsers_config(self, parser_command):
        """Test disable parser when parsers config doesn't exist"""
        # Arrange
        mock_config = {}  # No parsers key

        with patch.object(
            parser_command, "_get_config_path", return_value=Path("/fake/config.json")
        ), patch.object(
            parser_command, "_load_config", return_value=mock_config
        ), patch.object(
            parser_command, "_save_config"
        ) as mock_save:
            # Act
            result = await parser_command._disable_parser(["python"])

        # Assert
        assert result.success is True
        assert "disabled" in result.output
        mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_disable_parser_handles_exception(self, parser_command):
        """Test disable parser handles exceptions"""
        # Arrange
        with patch.object(
            parser_command,
            "_get_config_path",
            side_effect=RuntimeError("Config error"),
        ):
            # Act
            result = await parser_command._disable_parser(["python"])

        # Assert
        assert result.success is False
        assert "Failed to disable parser" in result.error
        assert result.exit_code == 1


class TestTestParser:
    """Tests for _test_parser subcommand"""

    @pytest.mark.asyncio
    async def test_test_parser_without_args(self, parser_command):
        """Test test parser without file path"""
        # Act
        result = await parser_command._test_parser([])

        # Assert
        assert result.success is False
        assert "Usage:" in result.error
        assert result.exit_code == 2

    @pytest.mark.asyncio
    async def test_test_parser_with_nonexistent_file(self, parser_command):
        """Test test parser with nonexistent file"""
        # Arrange
        with patch("pathlib.Path.exists", return_value=False):
            # Act
            result = await parser_command._test_parser(["/fake/file.py"])

        # Assert
        assert result.success is False
        assert "File not found" in result.error
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_test_parser_with_valid_file(self, parser_command):
        """Test test parser with valid file"""
        # Arrange
        mock_parser = Mock()
        mock_parser.__class__.__name__ = "PythonParser"
        mock_parser.metadata = Mock(
            name="PythonParser",
            priority=100,
            supported_extensions=[".py"],
            description="Parse Python plugins",
        )

        mock_loader = Mock()
        mock_loader.parser_registry.get_parser.return_value = mock_parser

        with patch("pathlib.Path.exists", return_value=True), patch.object(
            parser_command, "_load_parser_config", return_value={}
        ), patch(
            "gscripts.cli.command_classes.parser_command.RefactoredPluginLoader",
            return_value=mock_loader,
        ):
            # Act
            result = await parser_command._test_parser(["/fake/plugin.py"])

        # Assert
        assert result.success is True
        assert "Can be parsed by" in result.output
        assert "PythonParser" in result.output

    @pytest.mark.asyncio
    async def test_test_parser_with_no_matching_parser(self, parser_command):
        """Test test parser with no matching parser"""
        # Arrange
        mock_loader = Mock()
        mock_loader.parser_registry.get_parser.side_effect = ValueError(
            "No parser found"
        )

        with patch("pathlib.Path.exists", return_value=True), patch.object(
            parser_command, "_load_parser_config", return_value={}
        ), patch(
            "gscripts.cli.command_classes.parser_command.RefactoredPluginLoader",
            return_value=mock_loader,
        ):
            # Act
            result = await parser_command._test_parser(["/fake/unknown.txt"])

        # Assert
        assert result.success is False
        assert "No parser found" in result.error
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_test_parser_handles_exception(self, parser_command):
        """Test test parser handles exceptions"""
        # Arrange
        with patch.object(
            parser_command,
            "_load_parser_config",
            side_effect=RuntimeError("Config error"),
        ), patch("pathlib.Path.exists", return_value=True):
            # Act
            result = await parser_command._test_parser(["/fake/plugin.py"])

        # Assert
        assert result.success is False
        assert "Failed to test parser" in result.error
        assert result.exit_code == 1


class TestConfigHelpers:
    """Tests for configuration helper methods"""

    def test_get_config_path(self, parser_command):
        """Test _get_config_path returns correct path"""
        # Act
        result = parser_command._get_config_path()

        # Assert
        assert isinstance(result, Path)
        assert result.name == "gs.json"

    def test_load_config_success(self, parser_command):
        """Test _load_config loads JSON successfully"""
        # Arrange
        mock_config_data = {"parsers": {"enabled": ["python"]}}
        mock_json = json.dumps(mock_config_data)

        with patch("builtins.open", mock_open(read_data=mock_json)):
            # Act
            result = parser_command._load_config(Path("/fake/config.json"))

        # Assert
        assert result == mock_config_data

    def test_save_config_success(self, parser_command):
        """Test _save_config writes JSON successfully"""
        # Arrange
        mock_config_data = {"parsers": {"enabled": ["python"]}}

        with patch("builtins.open", mock_open()) as mock_file:
            # Act
            parser_command._save_config(Path("/fake/config.json"), mock_config_data)

        # Assert
        mock_file.assert_called_once()

    def test_load_parser_config_success(self, parser_command):
        """Test _load_parser_config loads parser config"""
        # Arrange
        mock_config = {"parsers": {"enabled": ["python"], "disabled": []}}

        with patch.object(
            parser_command, "_get_config_path", return_value=Path("/fake/config.json")
        ), patch.object(parser_command, "_load_config", return_value=mock_config):
            # Act
            result = parser_command._load_parser_config()

        # Assert
        assert result == {"enabled": ["python"], "disabled": []}

    def test_load_parser_config_returns_empty_on_error(self, parser_command):
        """Test _load_parser_config returns empty dict on error"""
        # Arrange
        with patch.object(
            parser_command, "_get_config_path", side_effect=RuntimeError("Error")
        ):
            # Act
            result = parser_command._load_parser_config()

        # Assert
        assert result == {}
