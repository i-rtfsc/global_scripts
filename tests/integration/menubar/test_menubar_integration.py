"""
Integration tests for CLI → Menu Bar communication

Tests the full flow from command execution to IPC messages
"""

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Only run these tests on macOS or if explicitly requested
pytestmark = pytest.mark.skipif(
    os.sys.platform != "darwin" and not os.getenv("FORCE_MENUBAR_TESTS"),
    reason="Menubar integration tests only run on macOS",
)


@pytest.fixture
def temp_socket_path(tmp_path):
    """Provide temporary socket path for IPC"""
    return tmp_path / "test_menubar.sock"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_plugin_executor_sends_ipc_messages(temp_socket_path):
    """Test PluginExecutor sends IPC messages during command execution"""
    from gscripts.application.services.plugin_executor import PluginExecutor
    from gscripts.menubar.ipc import IPCServer
    from gscripts.models import CommandResult

    # Track messages received
    messages_received = []

    def message_handler(msg):
        messages_received.append(msg)

    # Start IPC server
    server = IPCServer(socket_path=temp_socket_path, message_handler=message_handler)

    try:
        await server.start()
        await asyncio.sleep(0.1)

        # Create mock plugin loader
        mock_loader = MagicMock()
        mock_loader.get_loaded_plugins.return_value = {
            "test": {
                "enabled": True,
                "functions": {
                    "testfunc": {
                        "type": "python",
                        "python_file": "/tmp/nonexistent.py",
                        "name": "testfunc",
                    }
                },
            }
        }

        # Create mock process executor
        mock_process_executor = MagicMock()

        # Create executor
        executor = PluginExecutor(
            plugin_loader=mock_loader, process_executor=mock_process_executor
        )

        # Mock the actual python execution to avoid file I/O
        async def mock_execute_python(*args, **kwargs):
            return CommandResult(success=True, output="Test output")

        # Patch IPC socket path and execute
        with patch("gscripts.menubar.ipc.get_socket_path", return_value=temp_socket_path):
            with patch.object(
                executor, "_execute_python_function", side_effect=mock_execute_python
            ):
                result = await executor.execute_plugin_function("test", "testfunc", [])

                # Give time for IPC messages to be processed
                await asyncio.sleep(0.2)

                # Verify result
                assert result.success is True

                # Verify IPC messages were sent
                assert len(messages_received) >= 2

                # Check command_start message
                start_msgs = [m for m in messages_received if m.get("type") == "command_start"]
                assert len(start_msgs) == 1
                assert start_msgs[0]["command"] == "test.testfunc"

                # Check command_complete message
                complete_msgs = [
                    m for m in messages_received if m.get("type") == "command_complete"
                ]
                assert len(complete_msgs) == 1
                assert complete_msgs[0]["success"] is True

    finally:
        await server.stop()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_plugin_executor_progress_reporting(temp_socket_path):
    """Test PluginExecutor sends progress updates for generator functions"""
    from gscripts.application.services.plugin_executor import PluginExecutor
    from gscripts.menubar.ipc import IPCServer
    from gscripts.models import CommandResult

    messages_received = []

    def message_handler(msg):
        messages_received.append(msg)

    server = IPCServer(socket_path=temp_socket_path, message_handler=message_handler)

    try:
        await server.start()
        await asyncio.sleep(0.1)

        # Create mock plugin loader
        mock_loader = MagicMock()
        mock_loader.get_loaded_plugins.return_value = {
            "test": {
                "enabled": True,
                "functions": {
                    "testfunc": {
                        "type": "python",
                        "python_file": "/tmp/nonexistent.py",
                        "name": "testfunc",
                    }
                },
            }
        }

        mock_process_executor = MagicMock()
        executor = PluginExecutor(
            plugin_loader=mock_loader, process_executor=mock_process_executor
        )

        # Mock python execution that yields progress
        async def mock_execute_python_generator(*args, **kwargs):
            async def generator():
                yield {"progress": 25}
                await asyncio.sleep(0.05)
                yield {"progress": 50}
                await asyncio.sleep(0.05)
                yield {"progress": 75}
                await asyncio.sleep(0.05)
                yield CommandResult(success=True, output="Done")

            return generator()

        with patch("gscripts.menubar.ipc.get_socket_path", return_value=temp_socket_path):
            with patch.object(
                executor,
                "_execute_python_function",
                side_effect=mock_execute_python_generator,
            ):
                result = await executor.execute_plugin_function("test", "testfunc", [])

                await asyncio.sleep(0.3)

                assert result.success is True

                # Verify progress updates were sent
                progress_msgs = [
                    m for m in messages_received if m.get("type") == "progress_update"
                ]
                assert len(progress_msgs) == 3

                # Verify progress percentages
                percentages = [m["percentage"] for m in progress_msgs]
                assert 25 in percentages
                assert 50 in percentages
                assert 75 in percentages

    finally:
        await server.stop()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_nested_command_execution_no_duplicate_ipc(temp_socket_path):
    """Test nested command execution doesn't send duplicate IPC messages"""
    from gscripts.application.services.plugin_executor import PluginExecutor
    from gscripts.menubar.ipc import IPCServer
    from gscripts.models import CommandResult

    messages_received = []

    def message_handler(msg):
        messages_received.append(msg)

    server = IPCServer(socket_path=temp_socket_path, message_handler=message_handler)

    try:
        await server.start()
        await asyncio.sleep(0.1)

        # Create executor with mock dependencies
        mock_loader = MagicMock()
        mock_loader.get_loaded_plugins.return_value = {
            "outer": {
                "enabled": True,
                "functions": {
                    "outer_func": {
                        "type": "python",
                        "python_file": "/tmp/outer.py",
                        "name": "outer_func",
                    }
                },
            },
            "inner": {
                "enabled": True,
                "functions": {
                    "inner_func": {
                        "type": "python",
                        "python_file": "/tmp/inner.py",
                        "name": "inner_func",
                    }
                },
            },
        }

        mock_process_executor = MagicMock()
        executor = PluginExecutor(
            plugin_loader=mock_loader, process_executor=mock_process_executor
        )

        # Track execution calls
        execution_calls = []

        original_execute_python = executor._execute_python_function

        async def tracking_execute_python(function_info, args, start_time=None):
            execution_calls.append(function_info.get("name"))

            # If outer function, call inner
            if function_info.get("name") == "outer_func":
                # Simulate nested call
                await executor.execute_plugin_function("inner", "inner_func", [])

            return CommandResult(success=True, output=f"Executed {function_info.get('name')}")

        with patch("gscripts.menubar.ipc.get_socket_path", return_value=temp_socket_path):
            with patch.object(
                executor, "_execute_python_function", side_effect=tracking_execute_python
            ):
                # Execute outer function (which calls inner)
                result = await executor.execute_plugin_function("outer", "outer_func", [])

                await asyncio.sleep(0.2)

                assert result.success is True

                # Should have executed both functions
                assert "outer_func" in execution_calls
                assert "inner_func" in execution_calls

                # But only outer should have sent IPC messages
                start_msgs = [m for m in messages_received if m.get("type") == "command_start"]
                # Should only have 1 command_start (for outer, not inner)
                assert len(start_msgs) == 1
                assert start_msgs[0]["command"] == "outer.outer_func"

    finally:
        await server.stop()


@pytest.mark.integration
def test_cli_menubar_auto_start_integration(tmp_path):
    """Test CLI auto-starts menu bar when enabled"""
    from gscripts.menubar.utils import ensure_menubar_running

    # Mock config with menubar enabled
    config = {"menubar": {"enabled": True}}

    pid_file = tmp_path / "menubar.pid"

    with patch("sys.platform", "darwin"):
        with patch("gscripts.menubar.utils.get_pid_file", return_value=pid_file):
            with patch("gscripts.menubar.utils.start_menubar") as mock_start:
                mock_start.return_value = True

                result = ensure_menubar_running(config)

                assert result is True
                mock_start.assert_called_once()


@pytest.mark.integration
def test_cli_menubar_skip_when_disabled(tmp_path):
    """Test CLI skips menu bar when disabled"""
    from gscripts.menubar.utils import ensure_menubar_running

    # Mock config with menubar disabled
    config = {"menubar": {"enabled": False}}

    with patch("sys.platform", "darwin"):
        with patch("gscripts.menubar.utils.start_menubar") as mock_start:
            result = ensure_menubar_running(config)

            assert result is False
            mock_start.assert_not_called()
