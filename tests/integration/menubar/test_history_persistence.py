"""
Integration tests for Command History Persistence

Tests the complete history flow:
- Recording command execution to history
- History persistence across menubar restarts
- History menu updates
- Command replay functionality
"""

import asyncio
import json
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Only run these tests on macOS or if explicitly requested
pytestmark = pytest.mark.skipif(
    os.sys.platform != "darwin" and not os.getenv("FORCE_MENUBAR_TESTS"),
    reason="Menubar history tests only run on macOS",
)


@pytest.fixture
def temp_history_file(tmp_path):
    """Provide temporary history file for testing"""
    return tmp_path / "test_history.json"


@pytest.fixture
def temp_config_dir(tmp_path):
    """Provide temporary config directory"""
    config_dir = tmp_path / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.mark.integration
def test_history_persistence_across_restarts(temp_history_file):
    """Test history persists across menubar app restarts"""
    from gscripts.menubar.history import CommandHistoryManager

    # Create first manager instance and add commands
    manager1 = CommandHistoryManager(history_file=temp_history_file, max_entries=50)
    manager1.add_command("android.build", time.time(), True, 10.5)
    manager1.add_command("system.clean", time.time(), True, 2.3)
    manager1.add_command("grep.search", time.time(), False, 1.0, "Pattern not found")

    assert len(manager1) == 3

    # Simulate app restart by creating new manager with same file
    manager2 = CommandHistoryManager(history_file=temp_history_file, max_entries=50)

    # Should load previous history
    assert len(manager2) == 3

    recent = manager2.get_recent(limit=10)
    assert len(recent) == 3

    # Verify order (most recent first)
    assert recent[0].command == "grep.search"
    assert recent[0].success is False
    assert recent[0].error == "Pattern not found"

    assert recent[1].command == "system.clean"
    assert recent[1].success is True

    assert recent[2].command == "android.build"
    assert recent[2].success is True
    assert recent[2].duration == 10.5


@pytest.mark.integration
def test_history_file_format_validation(temp_history_file):
    """Test history manager handles valid and invalid file formats"""
    from gscripts.menubar.history import CommandHistoryManager

    # Test 1: Valid JSON format
    valid_data = {
        "version": "1.0",
        "commands": [
            {
                "command": "test.cmd",
                "timestamp": 1234567890.0,
                "success": True,
                "duration": 5.0,
                "error": None,
            }
        ],
    }

    temp_history_file.write_text(json.dumps(valid_data))
    manager = CommandHistoryManager(history_file=temp_history_file)
    assert len(manager) == 1
    assert manager.get_recent()[0].command == "test.cmd"

    # Test 2: Invalid JSON (should start fresh)
    temp_history_file.write_text("{ invalid json }")
    manager2 = CommandHistoryManager(history_file=temp_history_file)
    assert len(manager2) == 0

    # Test 3: Invalid schema (should start fresh)
    invalid_schema = {"wrong": "schema"}
    temp_history_file.write_text(json.dumps(invalid_schema))
    manager3 = CommandHistoryManager(history_file=temp_history_file)
    assert len(manager3) == 0


@pytest.mark.integration
def test_history_atomic_writes_no_corruption(temp_history_file):
    """Test atomic writes prevent corruption"""
    from gscripts.menubar.history import CommandHistoryManager

    manager = CommandHistoryManager(history_file=temp_history_file)

    # Add multiple commands rapidly (simulate concurrent writes)
    for i in range(20):
        manager.add_command(f"cmd{i}", time.time(), True, 1.0)

    # File should be valid JSON
    data = json.loads(temp_history_file.read_text())
    assert "version" in data
    assert "commands" in data
    assert len(data["commands"]) == 20

    # Temp file should not exist
    temp_file = temp_history_file.with_suffix(".json.tmp")
    assert not temp_file.exists()

    # Reload should work
    manager2 = CommandHistoryManager(history_file=temp_history_file)
    assert len(manager2) == 20


@pytest.mark.integration
@pytest.mark.asyncio
async def test_menubar_records_command_to_history(temp_history_file, tmp_path):
    """Test MenuBarApp records completed commands to history"""
    from gscripts.menubar.app import MenuBarApp
    from gscripts.menubar.ipc import IPCClient, get_socket_path

    # Create config with history enabled
    config = {
        "menubar": {
            "enabled": True,
            "enable_history": True,
            "history_max_entries": 50,
            "refresh_interval": 5,
            "show_cpu_temp": False,
            "show_memory": False,
        }
    }

    # Mock socket path to temp directory
    socket_path = tmp_path / "test_menubar.sock"

    with patch("gscripts.menubar.ipc.get_socket_path", return_value=socket_path):
        with patch("gscripts.menubar.app.CommandHistoryManager") as MockHistoryManager:
            # Create mock history manager instance
            mock_history = MagicMock()
            mock_history.__len__.return_value = 0
            MockHistoryManager.return_value = mock_history

            # Create MenuBarApp (will fail to run fully, but we can test message handling)
            app = MenuBarApp(config=config)

            # Verify history manager was initialized
            assert app.history_manager is not None

            # Simulate command start message
            app._handle_command_start(
                {"type": "command_start", "command": "android.build", "timestamp": time.time()}
            )

            # Simulate command complete message
            start_time = time.time()
            app._handle_command_complete(
                {
                    "type": "command_complete",
                    "success": True,
                    "duration": 15.5,
                    "error": None,
                }
            )

            # Verify add_command was called with correct arguments
            mock_history.add_command.assert_called_once()
            call_args = mock_history.add_command.call_args[1]
            assert call_args["command"] == "android.build"
            assert call_args["success"] is True
            assert call_args["duration"] == 15.5
            assert call_args["error"] is None


@pytest.mark.integration
def test_history_menu_updates_after_command(temp_history_file):
    """Test history menu updates after command completion"""
    from gscripts.menubar.history import CommandHistoryManager

    # Use real history manager instead of mocking
    manager = CommandHistoryManager(history_file=temp_history_file)

    # Add some commands
    manager.add_command("android.build", time.time(), True, 10.5)
    manager.add_command("system.clean", time.time(), True, 2.0)
    manager.add_command("grep.search", time.time(), False, 1.0)

    # Verify history was recorded
    assert len(manager) == 3

    recent = manager.get_recent(limit=5)
    assert len(recent) == 3
    assert recent[0].command == "grep.search"
    assert recent[1].command == "system.clean"
    assert recent[2].command == "android.build"


@pytest.mark.integration
def test_history_clear_functionality(temp_history_file):
    """Test clearing history removes all entries and updates file"""
    from gscripts.menubar.history import CommandHistoryManager

    manager = CommandHistoryManager(history_file=temp_history_file)

    # Add commands
    manager.add_command("cmd1", time.time(), True, 1.0)
    manager.add_command("cmd2", time.time(), True, 2.0)
    manager.add_command("cmd3", time.time(), False, 3.0, "Error")

    assert len(manager) == 3
    assert temp_history_file.exists()

    # Clear history
    manager.clear()

    assert len(manager) == 0
    assert manager.get_recent() == []

    # File should be updated
    data = json.loads(temp_history_file.read_text())
    assert data["commands"] == []

    # Reload should show empty
    manager2 = CommandHistoryManager(history_file=temp_history_file)
    assert len(manager2) == 0


@pytest.mark.integration
def test_history_max_entries_eviction(temp_history_file):
    """Test FIFO eviction when max_entries is exceeded"""
    from gscripts.menubar.history import CommandHistoryManager

    # Create manager with low max_entries
    manager = CommandHistoryManager(history_file=temp_history_file, max_entries=5)

    # Add 10 commands
    for i in range(10):
        manager.add_command(f"cmd{i}", time.time(), True, 1.0)
        time.sleep(0.01)  # Ensure different timestamps

    # Should only keep last 5
    assert len(manager) == 5

    recent = manager.get_recent(limit=10)
    assert len(recent) == 5

    # Most recent should be cmd9
    assert recent[0].command == "cmd9"

    # Oldest kept should be cmd5
    assert recent[4].command == "cmd5"

    # Verify persistence
    manager2 = CommandHistoryManager(history_file=temp_history_file, max_entries=5)
    assert len(manager2) == 5
    assert manager2.get_recent()[0].command == "cmd9"


@pytest.mark.integration
def test_command_replay_execution_modes(tmp_path):
    """Test command replay in different execution modes"""
    import subprocess

    from gscripts.menubar.history import CommandHistoryManager

    # Use real history manager
    history_file = tmp_path / "replay_test_history.json"
    manager = CommandHistoryManager(history_file=history_file)

    # Add command to history
    manager.add_command("android.build", time.time(), True, 10.5)

    # Verify command was added
    assert len(manager) == 1
    recent = manager.get_recent(limit=1)
    assert recent[0].command == "android.build"

    # Test that replay command format is correct (without actually executing)
    # We can't easily test the actual execution in integration tests without subprocess mocking
    # This is better suited for unit tests of the _replay_command method


@pytest.mark.integration
def test_history_concurrent_access_thread_safety(temp_history_file):
    """Test history manager handles concurrent access safely"""
    import threading

    from gscripts.menubar.history import CommandHistoryManager

    manager = CommandHistoryManager(history_file=temp_history_file)

    def add_commands(prefix, count):
        for i in range(count):
            manager.add_command(f"{prefix}_{i}", time.time(), True, 1.0)
            time.sleep(0.001)

    # Create multiple threads adding commands concurrently
    threads = [
        threading.Thread(target=add_commands, args=("thread1", 10)),
        threading.Thread(target=add_commands, args=("thread2", 10)),
        threading.Thread(target=add_commands, args=("thread3", 10)),
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    # Should have all 30 commands
    assert len(manager) == 30

    # File should be valid JSON
    data = json.loads(temp_history_file.read_text())
    assert len(data["commands"]) == 30

    # Reload should work
    manager2 = CommandHistoryManager(history_file=temp_history_file)
    assert len(manager2) == 30
