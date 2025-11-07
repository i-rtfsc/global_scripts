"""
Tests for CLI Formatters

Tests OutputFormatter and ChineseFormatter implementations.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from gscripts.cli.formatters import ChineseFormatter, OutputFormatter
from gscripts.models.result import CommandResult


# Fixtures
@pytest.fixture
def chinese_formatter():
    """ChineseFormatter instance"""
    return ChineseFormatter()


@pytest.fixture
def mock_i18n():
    """Mock I18nManager"""
    i18n = Mock()
    i18n.current_language = "zh"
    i18n.get_message = Mock(side_effect=lambda key, **kwargs: f"i18n:{key}")
    return i18n


@pytest.fixture
def mock_constants():
    """Mock GlobalConstants"""
    constants = Mock()
    constants.project_name = "Global Scripts"
    constants.project_version = "5.0.0"
    return constants


@pytest.fixture
def output_formatter(mock_i18n, mock_constants):
    """OutputFormatter instance with mocked dependencies"""
    with patch(
        "gscripts.cli.formatters.get_i18n_manager", return_value=mock_i18n
    ), patch("gscripts.cli.formatters.GlobalConstants", return_value=mock_constants):
        formatter = OutputFormatter(chinese=True)
        formatter.i18n = mock_i18n
        formatter.constants = mock_constants
        return formatter


class TestChineseFormatter:
    """Tests for ChineseFormatter utility methods"""

    def test_get_display_width_ascii(self, chinese_formatter):
        """Test display width calculation for ASCII characters"""
        # Act
        width = chinese_formatter.get_display_width("hello")

        # Assert
        assert width == 5

    def test_get_display_width_chinese(self, chinese_formatter):
        """Test display width calculation for Chinese characters"""
        # Act
        width = chinese_formatter.get_display_width("你好")

        # Assert
        assert width == 4  # Each Chinese character counts as 2

    def test_get_display_width_mixed(self, chinese_formatter):
        """Test display width calculation for mixed characters"""
        # Act
        width = chinese_formatter.get_display_width("hello你好")

        # Assert
        assert width == 9  # 5 ASCII + 4 Chinese

    def test_pad_text_left_align(self, chinese_formatter):
        """Test text padding with left alignment"""
        # Act
        result = chinese_formatter.pad_text("test", 10, align="left")

        # Assert
        assert result == "test      "
        assert len(result) == 10

    def test_pad_text_center_align(self, chinese_formatter):
        """Test text padding with center alignment"""
        # Act
        result = chinese_formatter.pad_text("test", 10, align="center")

        # Assert
        assert result.strip() == "test"
        assert len(result) == 10

    def test_pad_text_right_align(self, chinese_formatter):
        """Test text padding with right alignment"""
        # Act
        result = chinese_formatter.pad_text("test", 10, align="right")

        # Assert
        assert result == "      test"
        assert len(result) == 10

    def test_pad_text_no_padding_needed(self, chinese_formatter):
        """Test text padding when no padding is needed"""
        # Act
        result = chinese_formatter.pad_text("test", 4, align="left")

        # Assert
        assert result == "test"

    def test_format_title(self, chinese_formatter):
        """Test title formatting"""
        # Act
        result = chinese_formatter.format_title("Test Title", icon="🚀", width=20)

        # Assert
        assert "🚀 Test Title" in result
        assert "=" in result

    def test_format_section(self, chinese_formatter):
        """Test section formatting"""
        # Act
        result = chinese_formatter.format_section(
            "Section", icon="📋", content="Content"
        )

        # Assert
        assert "📋 Section:" in result
        assert "Content" in result

    def test_format_section_without_content(self, chinese_formatter):
        """Test section formatting without content"""
        # Act
        result = chinese_formatter.format_section("Section", icon="📋")

        # Assert
        assert "📋 Section:" in result
        assert result == "📋 Section:"

    def test_format_status_enabled(self, chinese_formatter):
        """Test status formatting when enabled"""
        # Act
        result = chinese_formatter.format_status("Active", is_enabled=True)

        # Assert
        assert "✅ Active" == result

    def test_format_status_disabled(self, chinese_formatter):
        """Test status formatting when disabled"""
        # Act
        result = chinese_formatter.format_status("Inactive", is_enabled=False)

        # Assert
        assert "❌ Inactive" == result

    def test_format_table_empty_data(self, chinese_formatter):
        """Test table formatting with empty data"""
        # Act
        result = chinese_formatter.format_table([], [])

        # Assert
        assert result == ""

    def test_format_table_with_data(self, chinese_formatter):
        """Test table formatting with data"""
        # Arrange
        headers = ["Name", "Value"]
        rows = [["test1", "value1"], ["test2", "value2"]]

        # Act
        result = chinese_formatter.format_table(headers, rows)

        # Assert
        assert result  # Non-empty
        # Rich table formatting makes exact assertion difficult, just check it's generated


class TestOutputFormatter:
    """Tests for OutputFormatter class"""

    def test_output_formatter_initialization(self, mock_i18n, mock_constants):
        """Test OutputFormatter initialization"""
        # Arrange & Act
        with patch(
            "gscripts.cli.formatters.get_i18n_manager", return_value=mock_i18n
        ), patch(
            "gscripts.cli.formatters.GlobalConstants", return_value=mock_constants
        ):
            formatter = OutputFormatter(chinese=True)

        # Assert
        assert formatter.chinese is True
        assert formatter.i18n is mock_i18n

    def test_format_title(self, output_formatter):
        """Test title formatting through OutputFormatter"""
        # Act
        result = output_formatter.format_title("Test Title", icon="🚀")

        # Assert
        assert "🚀 Test Title" in result

    def test_format_info_table_delegates(self, output_formatter):
        """Test format_info_table delegates to formatter"""
        # Arrange
        data = {"key": "value"}

        # Act
        result = output_formatter.format_info_table(data)

        # Assert
        assert result  # Delegation works, returns non-empty string

    def test_format_table_empty_data(self, output_formatter):
        """Test format_table with empty data"""
        # Act
        result = output_formatter.format_table([])

        # Assert
        assert result == ""

    def test_format_table_with_data(self, output_formatter):
        """Test format_table with data"""
        # Arrange
        data = [{"name": "test1", "value": "val1"}, {"name": "test2", "value": "val2"}]

        # Act
        result = output_formatter.format_table(data)

        # Assert
        assert result  # Non-empty result

    def test_format_command_result_success(self, output_formatter):
        """Test formatting successful command result"""
        # Arrange
        result = CommandResult(
            success=True, output="Command output", execution_time=0.5
        )

        # Act
        formatted = output_formatter.format_command_result(result)

        # Assert
        assert formatted  # Non-empty
        assert "✅" in formatted or "success" in formatted.lower()

    def test_format_command_result_failure(self, output_formatter):
        """Test formatting failed command result"""
        # Arrange
        result = CommandResult(
            success=False, error="Command failed", execution_time=0.3
        )

        # Act
        formatted = output_formatter.format_command_result(result)

        # Assert
        assert formatted  # Non-empty
        assert "❌" in formatted or "fail" in formatted.lower()

    def test_format_help_usage(self, output_formatter):
        """Test help usage formatting"""
        # Act
        with patch("shutil.get_terminal_size", return_value=MagicMock(columns=80)):
            result = output_formatter.format_help_usage()

        # Assert
        assert result  # Non-empty
        assert "i18n:" in result  # Has i18n messages

    def test_print_help_calls_format(self, output_formatter, capsys):
        """Test print_help calls format_help_usage"""
        # Arrange
        with patch.object(
            output_formatter, "format_help_usage", return_value="Help text"
        ):
            # Act
            output_formatter.print_help()

        # Assert
        captured = capsys.readouterr()
        assert "Help text" in captured.out

    def test_print_version_with_version_arg(self, output_formatter, capsys):
        """Test print_version with version argument"""
        # Act
        output_formatter.print_version(version="1.0.0")

        # Assert
        captured = capsys.readouterr()
        assert "1.0.0" in captured.out

    def test_print_version_reads_version_file(self, output_formatter, capsys):
        """Test print_version reads from VERSION file when no arg"""
        # Arrange
        mock_version_content = "2.0.0"

        with patch("pathlib.Path.exists", return_value=True), patch(
            "pathlib.Path.read_text", return_value=mock_version_content
        ):
            # Act
            output_formatter.print_version()

        # Assert - Version was printed
        captured = capsys.readouterr()
        assert "2.0.0" in captured.out

    def test_print_plugin_list_with_plugins(self, output_formatter, capsys):
        """Test print_plugin_list with plugins"""
        # Arrange
        enabled_plugins = [{"name": "plugin1", "version": "1.0.0", "enabled": True}]
        disabled_plugins = [{"name": "plugin2", "version": "2.0.0", "enabled": False}]

        with patch("shutil.get_terminal_size", return_value=MagicMock(columns=80)):
            # Act
            output_formatter.print_plugin_list(enabled_plugins, disabled_plugins)

        # Assert
        captured = capsys.readouterr()
        assert captured.out  # Printed something

    def test_print_plugin_info(self, output_formatter, capsys):
        """Test print_plugin_info"""
        # Arrange
        plugin_info = {
            "name": "test_plugin",
            "version": "1.0.0",
            "description": "Test description",
            "commands": [
                {
                    "command": "gs test cmd",
                    "description": "Test command",
                    "usage": "gs test cmd [args]",
                }
            ],
        }

        with patch("shutil.get_terminal_size", return_value=MagicMock(columns=80)):
            # Act
            output_formatter.print_plugin_info(plugin_info)

        # Assert
        captured = capsys.readouterr()
        assert captured.out  # Printed something

    def test_print_table(self, output_formatter, capsys):
        """Test print_table"""
        # Arrange
        headers = ["Name", "Value"]
        rows = [["item1", "val1"]]

        with patch("shutil.get_terminal_size", return_value=MagicMock(columns=80)):
            # Act
            output_formatter.print_table(headers, rows, title="Test Table")

        # Assert
        captured = capsys.readouterr()
        assert captured.out  # Printed something


class TestChineseFormatterInfoTable:
    """Tests for format_info_table static method"""

    def test_format_info_table_empty(self):
        """Test format_info_table with empty data"""
        # Act
        result = ChineseFormatter.format_info_table({})

        # Assert
        assert result == ""

    def test_format_info_table_with_data(self):
        """Test format_info_table with data"""
        # Arrange
        data = {"key1": "value1", "key2": "value2"}

        with patch("os.getenv", return_value="zh"):
            # Act
            result = ChineseFormatter.format_info_table(data)

        # Assert
        assert result  # Non-empty
        # Rich table formatting makes exact assertion difficult
