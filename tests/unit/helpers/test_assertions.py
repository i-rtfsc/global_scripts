"""
Tests for helper assertions
"""

import pytest

from tests.helpers.assertions import (
    assert_command_result_success,
    assert_command_result_failure,
    assert_plugin_loaded,
    assert_plugin_enabled,
    assert_plugin_disabled,
    assert_file_exists,
    assert_file_not_exists,
    assert_dict_contains,
    assert_list_contains_items,
)
from tests.factories import ResultFactory, PluginFactory


class TestAssertions:
    """Tests for custom assertion helpers"""

    def test_assert_command_result_success_with_success(self):
        """Test success assertion with successful result"""
        # Arrange
        result = ResultFactory.success(output="Done")

        # Act & Assert - should not raise
        assert_command_result_success(result)

    def test_assert_command_result_success_with_failure_raises(self):
        """Test success assertion with failed result raises"""
        # Arrange
        result = ResultFactory.failure(error="Error")

        # Act & Assert
        with pytest.raises(AssertionError, match="Command failed"):
            assert_command_result_success(result)

    def test_assert_command_result_success_checks_output(self):
        """Test success assertion checks expected output"""
        # Arrange
        result = ResultFactory.success(output="Actual output")

        # Act & Assert
        assert_command_result_success(result, expected_output="Actual output")

        with pytest.raises(AssertionError, match="Output mismatch"):
            assert_command_result_success(result, expected_output="Different")

    def test_assert_command_result_failure_with_failure(self):
        """Test failure assertion with failed result"""
        # Arrange
        result = ResultFactory.failure(error="Error message")

        # Act & Assert - should not raise
        assert_command_result_failure(result)

    def test_assert_command_result_failure_with_success_raises(self):
        """Test failure assertion with successful result raises"""
        # Arrange
        result = ResultFactory.success()

        # Act & Assert
        with pytest.raises(AssertionError, match="succeeded when failure"):
            assert_command_result_failure(result)

    def test_assert_plugin_loaded_with_loaded_plugin(self):
        """Test plugin loaded assertion with loaded plugin"""
        # Arrange
        plugins = {
            "plugin1": {"metadata": PluginFactory.create(name="plugin1")},
            "plugin2": {"metadata": PluginFactory.create(name="plugin2")},
        }

        # Act & Assert - should not raise
        assert_plugin_loaded(plugins, "plugin1")

    def test_assert_plugin_loaded_with_missing_plugin_raises(self):
        """Test plugin loaded assertion with missing plugin raises"""
        # Arrange
        plugins = {"plugin1": {}}

        # Act & Assert
        with pytest.raises(AssertionError, match="not found"):
            assert_plugin_loaded(plugins, "missing")

    def test_assert_plugin_enabled_with_enabled_plugin(self):
        """Test plugin enabled assertion"""
        # Arrange
        metadata = PluginFactory.create(enabled=True)

        # Act & Assert - should not raise
        assert_plugin_enabled(metadata)

    def test_assert_plugin_enabled_with_disabled_plugin_raises(self):
        """Test plugin enabled assertion with disabled plugin raises"""
        # Arrange
        metadata = PluginFactory.create_disabled()

        # Act & Assert
        with pytest.raises(AssertionError, match="is not enabled"):
            assert_plugin_enabled(metadata)

    def test_assert_plugin_disabled_with_disabled_plugin(self):
        """Test plugin disabled assertion"""
        # Arrange
        metadata = PluginFactory.create_disabled()

        # Act & Assert - should not raise
        assert_plugin_disabled(metadata)

    def test_assert_file_exists_with_existing_file(self, temp_dir):
        """Test file exists assertion with existing file"""
        # Arrange
        file_path = temp_dir / "test.txt"
        file_path.write_text("content")

        # Act & Assert - should not raise
        assert_file_exists(file_path)

    def test_assert_file_exists_with_missing_file_raises(self, temp_dir):
        """Test file exists assertion with missing file raises"""
        # Arrange
        file_path = temp_dir / "missing.txt"

        # Act & Assert
        with pytest.raises(AssertionError, match="does not exist"):
            assert_file_exists(file_path)

    def test_assert_file_not_exists_with_missing_file(self, temp_dir):
        """Test file not exists assertion"""
        # Arrange
        file_path = temp_dir / "missing.txt"

        # Act & Assert - should not raise
        assert_file_not_exists(file_path)

    def test_assert_dict_contains_with_matching_dict(self):
        """Test dict contains assertion with matching values"""
        # Arrange
        actual = {"key1": "value1", "key2": "value2", "extra": "ignored"}
        expected = {"key1": "value1", "key2": "value2"}

        # Act & Assert - should not raise
        assert_dict_contains(actual, expected)

    def test_assert_dict_contains_with_missing_key_raises(self):
        """Test dict contains assertion with missing key raises"""
        # Arrange
        actual = {"key1": "value1"}
        expected = {"key1": "value1", "key2": "value2"}

        # Act & Assert
        with pytest.raises(AssertionError, match="Missing key"):
            assert_dict_contains(actual, expected)

    def test_assert_dict_contains_with_nested_dict(self):
        """Test dict contains assertion with nested structures"""
        # Arrange
        actual = {
            "level1": {
                "level2": {"key": "value"},
                "extra": "ignored",
            }
        }
        expected = {"level1": {"level2": {"key": "value"}}}

        # Act & Assert - should not raise
        assert_dict_contains(actual, expected)

    def test_assert_list_contains_items_with_all_items(self):
        """Test list contains items assertion"""
        # Arrange
        actual = [1, 2, 3, 4, 5]
        expected = [2, 4]

        # Act & Assert - should not raise
        assert_list_contains_items(actual, expected)

    def test_assert_list_contains_items_with_missing_item_raises(self):
        """Test list contains items with missing item raises"""
        # Arrange
        actual = [1, 2, 3]
        expected = [2, 4]

        # Act & Assert
        with pytest.raises(AssertionError, match="not found"):
            assert_list_contains_items(actual, expected)
