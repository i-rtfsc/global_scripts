"""
Integration tests for Shortcuts feature

Tests the complete shortcuts flow:
- Configuration loading
- Menu building with shortcuts
- Shortcut execution (terminal and background modes)
- Config reload
"""

import asyncio
import os
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Only run these tests on macOS or if explicitly requested
pytestmark = pytest.mark.skipif(
    os.sys.platform != "darwin" and not os.getenv("FORCE_MENUBAR_TESTS"),
    reason="Menubar shortcuts tests only run on macOS",
)


@pytest.mark.integration
def test_shortcut_manager_with_valid_config():
    """Test ShortcutManager loads shortcuts from valid config"""
    from gscripts.menubar.shortcuts import ShortcutManager, ExecutionMode

    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "📊 状态检查": {
                "command": "gs status",
                "execution_mode": "terminal"
            },
            "🔄 同步代码": {
                "command": "gs multirepo sync mini-aosp",
                "execution_mode": "background"
            },
            "🧹 清理缓存": {
                "command": "gs system clean --all",
                "execution_mode": "background"
            },
        }
    }

    manager = ShortcutManager(config=config)

    assert manager.is_enabled()
    shortcuts = manager.get_shortcuts()
    assert len(shortcuts) == 3

    # Verify shortcut details
    assert "📊 状态检查" in shortcuts
    assert shortcuts["📊 状态检查"].command == "gs status"
    assert shortcuts["📊 状态检查"].execution_mode == ExecutionMode.TERMINAL

    assert "🔄 同步代码" in shortcuts
    assert shortcuts["🔄 同步代码"].execution_mode == ExecutionMode.BACKGROUND

    # Verify sorted labels
    labels = manager.get_sorted_labels()
    assert len(labels) == 3
    assert labels == sorted(["📊 状态检查", "🔄 同步代码", "🧹 清理缓存"])


@pytest.mark.integration
def test_terminal_shortcut_execution():
    """Test terminal mode shortcut opens Terminal.app"""
    from gscripts.menubar.shortcuts import ShortcutManager

    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "Test": {
                "command": "gs status",
                "execution_mode": "terminal"
            }
        }
    }

    manager = ShortcutManager(config=config)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        success = manager.execute_shortcut("Test")

        assert success is True

        # Verify Terminal.app was opened via osascript
        mock_run.assert_called_once()
        args, kwargs = mock_run.call_args
        assert args[0][0] == "osascript"
        assert args[0][1] == "-e"
        assert 'tell application "Terminal"' in args[0][2]
        assert "gs status" in args[0][2]


@pytest.mark.integration
def test_background_shortcut_execution_with_callbacks():
    """Test background mode shortcut execution with callbacks"""
    from gscripts.menubar.shortcuts import ShortcutManager

    on_start_calls = []
    on_complete_calls = []

    def on_start(label, command):
        on_start_calls.append((label, command))

    def on_complete(success, duration, error):
        on_complete_calls.append((success, duration, error))

    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "Echo Test": {
                "command": "echo 'test output'",
                "execution_mode": "background"
            }
        }
    }

    manager = ShortcutManager(
        config=config,
        on_background_start=on_start,
        on_background_complete=on_complete
    )

    success = manager.execute_shortcut("Echo Test")
    assert success is True

    # Verify start callback was called
    assert len(on_start_calls) == 1
    assert on_start_calls[0][0] == "Echo Test"
    assert on_start_calls[0][1] == "echo 'test output'"

    # Wait for background thread to complete
    time.sleep(0.5)

    # Verify complete callback was called
    assert len(on_complete_calls) == 1
    success, duration, error = on_complete_calls[0]
    assert success is True
    assert duration > 0
    assert error is None


@pytest.mark.integration
def test_background_shortcut_failure_handling():
    """Test background shortcut handles command failure correctly"""
    from gscripts.menubar.shortcuts import ShortcutManager

    on_complete_calls = []

    def on_complete(success, duration, error):
        on_complete_calls.append((success, duration, error))

    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "Failing Command": {
                "command": "exit 1",  # Fail immediately
                "execution_mode": "background"
            }
        }
    }

    manager = ShortcutManager(
        config=config,
        on_background_complete=on_complete
    )

    success = manager.execute_shortcut("Failing Command")
    assert success is True  # Execution *started* successfully

    # Wait for background thread to complete
    time.sleep(0.5)

    # Verify complete callback reports failure
    assert len(on_complete_calls) == 1
    success, duration, error = on_complete_calls[0]
    assert success is False
    assert duration > 0
    assert error is not None  # Should have error message


@pytest.mark.integration
def test_config_reload_workflow():
    """Test complete config reload workflow"""
    from gscripts.menubar.shortcuts import ShortcutManager

    # Initial config
    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "Old Shortcut": {
                "command": "gs old",
                "execution_mode": "terminal"
            }
        }
    }

    manager = ShortcutManager(config=config)

    assert manager.is_enabled()
    assert "Old Shortcut" in manager.get_shortcuts()
    assert len(manager.get_shortcuts()) == 1

    # Reload with new config
    new_config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "New Shortcut 1": {
                "command": "gs new1",
                "execution_mode": "terminal"
            },
            "New Shortcut 2": {
                "command": "gs new2",
                "execution_mode": "background"
            }
        }
    }

    count = manager.reload_config(new_config)

    assert count == 2
    assert manager.is_enabled()
    assert "Old Shortcut" not in manager.get_shortcuts()
    assert "New Shortcut 1" in manager.get_shortcuts()
    assert "New Shortcut 2" in manager.get_shortcuts()


@pytest.mark.integration
def test_shortcuts_disabled_via_config_reload():
    """Test disabling shortcuts via config reload"""
    from gscripts.menubar.shortcuts import ShortcutManager

    # Start with shortcuts enabled
    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "Test": {
                "command": "gs test",
                "execution_mode": "terminal"
            }
        }
    }

    manager = ShortcutManager(config=config)
    assert manager.is_enabled()

    # Reload with shortcuts disabled
    new_config = {
        "enable_shortcuts": False,
        "shortcuts": {
            "Test": {
                "command": "gs test",
                "execution_mode": "terminal"
            }
        }
    }

    count = manager.reload_config(new_config)

    assert count == 0
    assert not manager.is_enabled()
    assert len(manager.get_shortcuts()) == 0


@pytest.mark.integration
def test_mixed_valid_and_invalid_shortcuts():
    """Test that valid shortcuts load even when some are invalid"""
    from gscripts.menubar.shortcuts import ShortcutManager

    config = {
        "enable_shortcuts": True,
        "shortcuts": {
            "Valid 1": {
                "command": "gs status",
                "execution_mode": "terminal"
            },
            "Invalid Mode": {
                "command": "gs test",
                "execution_mode": "invalid_mode"  # Invalid
            },
            "Valid 2": {
                "command": "gs clean",
                "execution_mode": "background"
            },
            "No Command": {
                "execution_mode": "terminal"  # Missing command
            },
            "Valid 3": {
                "command": "gs restart",
                "execution_mode": "terminal"
            }
        }
    }

    manager = ShortcutManager(config=config)

    # Only 3 valid shortcuts should be loaded
    shortcuts = manager.get_shortcuts()
    assert len(shortcuts) == 3
    assert "Valid 1" in shortcuts
    assert "Valid 2" in shortcuts
    assert "Valid 3" in shortcuts
    assert "Invalid Mode" not in shortcuts
    assert "No Command" not in shortcuts
