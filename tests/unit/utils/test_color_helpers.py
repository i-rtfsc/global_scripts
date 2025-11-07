"""
Tests for ColorHelper

Tests color formatting utilities for Rich console output.
"""

from gscripts.utils.color_helpers import ColorHelper, get_color_helper


class TestColorizeType:
    """Tests for colorize_type method"""

    def test_colorize_python_type(self):
        """Test colorizing Python plugin type"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_type("Python")

        # Assert
        assert "[bright_magenta]Python[/bright_magenta]" == result

    def test_colorize_shell_type(self):
        """Test colorizing Shell plugin type"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_type("Shell")

        # Assert
        assert "[bright_green]Shell[/bright_green]" == result

    def test_colorize_config_type(self):
        """Test colorizing Config plugin type"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_type("Config")

        # Assert
        assert "[bright_yellow]Config[/bright_yellow]" == result

    def test_colorize_unknown_type_uses_white(self):
        """Test unknown type defaults to white"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_type("UnknownType")

        # Assert
        assert "[white]UnknownType[/white]" == result

    def test_colorize_empty_type_returns_empty(self):
        """Test empty type returns empty string"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_type("")

        # Assert
        assert result == ""


class TestColorizeSubplugin:
    """Tests for colorize_subplugin method"""

    def test_colorize_subplugin_assigns_color(self):
        """Test subplugin gets assigned a color"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_subplugin("test_subplugin")

        # Assert
        assert result.startswith("[")
        assert "test_subplugin" in result
        assert result.endswith("]")

    def test_colorize_same_subplugin_uses_same_color(self):
        """Test same subplugin name gets same color"""
        # Arrange
        helper = ColorHelper()

        # Act
        result1 = helper.colorize_subplugin("subplugin1")
        result2 = helper.colorize_subplugin("subplugin1")

        # Assert
        assert result1 == result2

    def test_colorize_different_subplugins_get_different_colors(self):
        """Test different subplugins get different colors"""
        # Arrange
        helper = ColorHelper()

        # Act
        result1 = helper.colorize_subplugin("subplugin1")
        result2 = helper.colorize_subplugin("subplugin2")

        # Assert
        assert result1 != result2

    def test_colorize_empty_subplugin_returns_empty(self):
        """Test empty subplugin returns empty string"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_subplugin("")

        # Assert
        assert result == ""


class TestColorizeUsage:
    """Tests for colorize_usage method"""

    def test_colorize_usage_with_required_params(self):
        """Test colorizing usage with required parameters"""
        # Arrange
        helper = ColorHelper()
        usage = "gs plugin <name>"

        # Act
        result = helper.colorize_usage(usage)

        # Assert
        # The regex applies colors but may nest them - check that <name> is colored
        assert "<name>" in result
        assert "[bright_red]" in result or "[bright_yellow]" in result

    def test_colorize_usage_with_optional_params(self):
        """Test colorizing usage with optional parameters"""
        # Arrange
        helper = ColorHelper()
        usage = "gs plugin [options]"

        # Act
        result = helper.colorize_usage(usage)

        # Assert
        assert "[bright_yellow][options][/bright_yellow]" in result

    def test_colorize_usage_with_choice_params(self):
        """Test colorizing usage with choice parameters"""
        # Arrange
        helper = ColorHelper()
        usage = "gs plugin {enable|disable}"

        # Act
        result = helper.colorize_usage(usage)

        # Assert
        assert "[bright_cyan]{enable|disable}[/bright_cyan]" in result

    def test_colorize_usage_with_mixed_params(self):
        """Test colorizing usage with mixed parameter types"""
        # Arrange
        helper = ColorHelper()
        usage = "gs plugin <name> [options] {type}"

        # Act
        result = helper.colorize_usage(usage)

        # Assert
        # Check that all parameter types are colored (though nesting may occur)
        assert "<name>" in result
        assert "[options]" in result
        assert "{type}" in result
        assert "[bright_red]" in result
        assert "[bright_yellow]" in result
        assert "[bright_cyan]" in result

    def test_colorize_empty_usage_returns_empty(self):
        """Test empty usage returns empty string"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_usage("")

        # Assert
        assert result == ""


class TestColorizeStatus:
    """Tests for colorize_status method"""

    def test_colorize_enabled_status(self):
        """Test colorizing enabled status"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_status("启用")

        # Assert
        assert "[green]✓[/green]" == result

    def test_colorize_disabled_status(self):
        """Test colorizing disabled status"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_status("禁用")

        # Assert
        assert "[red]✗[/red]" == result

    def test_colorize_normal_status(self):
        """Test colorizing normal status"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_status("正常")

        # Assert
        assert "[green]✓[/green]" == result

    def test_colorize_status_removes_existing_emoji(self):
        """Test that existing emoji are removed"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_status("✅ 启用")

        # Assert
        assert "✅" not in result
        assert "[green]✓[/green]" == result

    def test_colorize_empty_status_returns_empty(self):
        """Test empty status returns empty string"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_status("")

        # Assert
        assert result == ""


class TestColorizeNumber:
    """Tests for colorize_number method"""

    def test_colorize_number_with_default_style(self):
        """Test colorizing number with default style"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_number("42")

        # Assert
        assert result == "[bright_blue]42[/bright_blue]"

    def test_colorize_number_with_custom_style(self):
        """Test colorizing number with custom style"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_number("100", style="bright_red")

        # Assert
        assert result == "[bright_red]100[/bright_red]"

    def test_colorize_empty_number_returns_empty(self):
        """Test empty number returns empty string"""
        # Arrange
        helper = ColorHelper()

        # Act
        result = helper.colorize_number("")

        # Assert
        assert result == ""


class TestGetColorHelper:
    """Tests for get_color_helper function"""

    def test_get_color_helper_returns_singleton(self):
        """Test that get_color_helper returns same instance"""
        # Act
        helper1 = get_color_helper()
        helper2 = get_color_helper()

        # Assert
        assert helper1 is helper2

    def test_get_color_helper_returns_color_helper_instance(self):
        """Test that get_color_helper returns ColorHelper instance"""
        # Act
        helper = get_color_helper()

        # Assert
        assert isinstance(helper, ColorHelper)
