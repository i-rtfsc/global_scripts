"""
Custom assertions for testing.

Provides specialized assertion functions for common test scenarios.
"""

from typing import Optional, Any, List
from pathlib import Path

from gscripts.models.result import CommandResult
from gscripts.models.plugin import PluginMetadata


def assert_command_result_success(
    result: CommandResult,
    expected_output: Optional[str] = None,
    expected_exit_code: int = 0,
):
    """
    Assert command result indicates success.

    Args:
        result: Command result to check
        expected_output: Expected output (if specified)
        expected_exit_code: Expected exit code (default 0)

    Raises:
        AssertionError: If result doesn't indicate success
    """
    assert result.success, f"Command failed: {result.error}"
    assert (
        result.exit_code == expected_exit_code
    ), f"Exit code mismatch: expected {expected_exit_code}, got {result.exit_code}"

    if expected_output is not None:
        assert (
            result.output == expected_output
        ), f"Output mismatch: expected '{expected_output}', got '{result.output}'"


def assert_command_result_failure(
    result: CommandResult,
    expected_error: Optional[str] = None,
    expected_exit_code: int = 1,
):
    """
    Assert command result indicates failure.

    Args:
        result: Command result to check
        expected_error: Expected error message (if specified)
        expected_exit_code: Expected exit code (default 1)

    Raises:
        AssertionError: If result doesn't indicate failure
    """
    assert not result.success, "Command succeeded when failure was expected"
    assert (
        result.exit_code == expected_exit_code
    ), f"Exit code mismatch: expected {expected_exit_code}, got {result.exit_code}"

    if expected_error is not None:
        assert (
            expected_error in result.error
        ), f"Error message mismatch: expected '{expected_error}' in '{result.error}'"


def assert_plugin_loaded(
    plugins: dict,
    plugin_name: str,
):
    """
    Assert plugin is loaded in plugin dictionary.

    Args:
        plugins: Plugin dictionary from loader
        plugin_name: Name of plugin to check

    Raises:
        AssertionError: If plugin is not loaded
    """
    assert (
        plugin_name in plugins
    ), f"Plugin '{plugin_name}' not found in loaded plugins: {list(plugins.keys())}"


def assert_plugin_enabled(metadata: PluginMetadata):
    """
    Assert plugin is enabled.

    Args:
        metadata: Plugin metadata to check

    Raises:
        AssertionError: If plugin is not enabled
    """
    assert metadata.enabled, f"Plugin '{metadata.name}' is not enabled"


def assert_plugin_disabled(metadata: PluginMetadata):
    """
    Assert plugin is disabled.

    Args:
        metadata: Plugin metadata to check

    Raises:
        AssertionError: If plugin is enabled
    """
    assert not metadata.enabled, f"Plugin '{metadata.name}' is enabled"


def assert_file_exists(path: Path):
    """
    Assert file exists.

    Args:
        path: Path to check

    Raises:
        AssertionError: If file doesn't exist
    """
    assert path.exists(), f"File does not exist: {path}"


def assert_file_not_exists(path: Path):
    """
    Assert file does not exist.

    Args:
        path: Path to check

    Raises:
        AssertionError: If file exists
    """
    assert not path.exists(), f"File exists: {path}"


def assert_dict_contains(
    actual: dict,
    expected: dict,
    path: str = "",
):
    """
    Assert dict contains all expected keys/values (deep check).

    Args:
        actual: Actual dictionary
        expected: Expected keys/values
        path: Current path for error messages (internal)

    Raises:
        AssertionError: If expected keys/values are missing
    """
    for key, expected_value in expected.items():
        current_path = f"{path}.{key}" if path else key

        assert key in actual, f"Missing key '{current_path}' in actual dict"

        actual_value = actual[key]

        if isinstance(expected_value, dict):
            assert isinstance(
                actual_value, dict
            ), f"Value at '{current_path}' is not a dict"
            assert_dict_contains(actual_value, expected_value, current_path)
        else:
            assert (
                actual_value == expected_value
            ), f"Value mismatch at '{current_path}': expected {expected_value}, got {actual_value}"


def assert_list_contains_items(
    actual: List[Any],
    expected_items: List[Any],
):
    """
    Assert list contains all expected items (order-independent).

    Args:
        actual: Actual list
        expected_items: Items that must be present

    Raises:
        AssertionError: If any expected item is missing
    """
    for item in expected_items:
        assert item in actual, f"Expected item '{item}' not found in list: {actual}"


def assert_raises_with_message(
    exception_class: type, message: str, callable_obj: callable, *args, **kwargs
):
    """
    Assert callable raises exception with specific message.

    Args:
        exception_class: Expected exception class
        message: Expected message substring
        callable_obj: Function to call
        *args: Args for callable
        **kwargs: Kwargs for callable

    Raises:
        AssertionError: If exception not raised or message doesn't match
    """
    try:
        callable_obj(*args, **kwargs)
        raise AssertionError(f"Expected {exception_class.__name__} to be raised")
    except exception_class as e:
        assert message in str(
            e
        ), f"Exception message mismatch: expected '{message}' in '{str(e)}'"
    except Exception as e:
        raise AssertionError(
            f"Wrong exception type: expected {exception_class.__name__}, got {type(e).__name__}"
        )
