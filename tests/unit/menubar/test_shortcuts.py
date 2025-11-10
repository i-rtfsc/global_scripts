"""
Unit tests for menubar shortcuts module
"""

import pytest
from unittest.mock import MagicMock, patch, call


class TestShortcut:
    """Tests for Shortcut dataclass"""

    @pytest.mark.unit
    def test_shortcut_creation(self):
        """Test Shortcut creation"""
        from gscripts.menubar.shortcuts import Shortcut, ExecutionMode

        shortcut = Shortcut(
            label="Test Shortcut",
            command="gs status",
            execution_mode=ExecutionMode.TERMINAL,
        )

        assert shortcut.label == "Test Shortcut"
        assert shortcut.command == "gs status"
        assert shortcut.execution_mode == ExecutionMode.TERMINAL

    @pytest.mark.unit
    def test_shortcut_empty_label_raises(self):
        """Test Shortcut raises on empty label"""
        from gscripts.menubar.shortcuts import Shortcut, ExecutionMode

        with pytest.raises(ValueError, match="label cannot be empty"):
            Shortcut(label="", command="gs status", execution_mode=ExecutionMode.TERMINAL)

    @pytest.mark.unit
    def test_shortcut_empty_command_raises(self):
        """Test Shortcut raises on empty command"""
        from gscripts.menubar.shortcuts import Shortcut, ExecutionMode

        with pytest.raises(ValueError, match="command cannot be empty"):
            Shortcut(label="Test", command="", execution_mode=ExecutionMode.TERMINAL)


class TestShortcutManager:
    """Tests for ShortcutManager"""

    @pytest.mark.unit
    def test_shortcuts_disabled_by_default(self):
        """Test shortcuts are disabled if not enabled in config"""
        from gscripts.menubar.shortcuts import ShortcutManager

        manager = ShortcutManager(config={})
        assert not manager.is_enabled()
        assert len(manager.get_shortcuts()) == 0

    @pytest.mark.unit
    def test_shortcuts_enabled_with_definitions(self):
        """Test shortcuts are enabled when configured"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Test": {"command": "gs status", "execution_mode": "terminal"}
            },
        }

        manager = ShortcutManager(config=config)
        assert manager.is_enabled()
        assert len(manager.get_shortcuts()) == 1

    @pytest.mark.unit
    def test_load_valid_shortcut(self):
        """Test loading a valid shortcut"""
        from gscripts.menubar.shortcuts import ShortcutManager, ExecutionMode

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Status Check": {
                    "command": "gs status",
                    "execution_mode": "terminal",
                }
            },
        }

        manager = ShortcutManager(config=config)
        shortcuts = manager.get_shortcuts()

        assert "Status Check" in shortcuts
        shortcut = shortcuts["Status Check"]
        assert shortcut.command == "gs status"
        assert shortcut.execution_mode == ExecutionMode.TERMINAL

    @pytest.mark.unit
    def test_load_multiple_shortcuts(self):
        """Test loading multiple shortcuts"""
        from gscripts.menubar.shortcuts import ShortcutManager, ExecutionMode

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Terminal": {"command": "gs status", "execution_mode": "terminal"},
                "Background": {
                    "command": "gs system restart",
                    "execution_mode": "background",
                },
            },
        }

        manager = ShortcutManager(config=config)
        shortcuts = manager.get_shortcuts()

        assert len(shortcuts) == 2
        assert "Terminal" in shortcuts
        assert "Background" in shortcuts
        assert shortcuts["Terminal"].execution_mode == ExecutionMode.TERMINAL
        assert shortcuts["Background"].execution_mode == ExecutionMode.BACKGROUND

    @pytest.mark.unit
    def test_sorted_labels(self):
        """Test get_sorted_labels returns alphabetically sorted labels"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Zebra": {"command": "gs z", "execution_mode": "terminal"},
                "Apple": {"command": "gs a", "execution_mode": "terminal"},
                "Mango": {"command": "gs m", "execution_mode": "terminal"},
            },
        }

        manager = ShortcutManager(config=config)
        labels = manager.get_sorted_labels()

        assert labels == ["Apple", "Mango", "Zebra"]

    @pytest.mark.unit
    def test_invalid_execution_mode_skipped(self):
        """Test shortcut with invalid execution_mode is skipped"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Valid": {"command": "gs status", "execution_mode": "terminal"},
                "Invalid": {"command": "gs test", "execution_mode": "invalid_mode"},
            },
        }

        manager = ShortcutManager(config=config)
        shortcuts = manager.get_shortcuts()

        assert len(shortcuts) == 1
        assert "Valid" in shortcuts
        assert "Invalid" not in shortcuts

    @pytest.mark.unit
    def test_missing_command_skipped(self):
        """Test shortcut with missing command is skipped"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Valid": {"command": "gs status", "execution_mode": "terminal"},
                "No Command": {"execution_mode": "terminal"},
            },
        }

        manager = ShortcutManager(config=config)
        shortcuts = manager.get_shortcuts()

        assert len(shortcuts) == 1
        assert "Valid" in shortcuts
        assert "No Command" not in shortcuts

    @pytest.mark.unit
    def test_empty_command_skipped(self):
        """Test shortcut with empty command is skipped"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Valid": {"command": "gs status", "execution_mode": "terminal"},
                "Empty": {"command": "", "execution_mode": "terminal"},
                "Whitespace": {"command": "   ", "execution_mode": "terminal"},
            },
        }

        manager = ShortcutManager(config=config)
        shortcuts = manager.get_shortcuts()

        assert len(shortcuts) == 1
        assert "Valid" in shortcuts
        assert "Empty" not in shortcuts
        assert "Whitespace" not in shortcuts

    @pytest.mark.unit
    def test_dangerous_command_warning(self):
        """Test dangerous commands trigger warning but still load"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Dangerous": {"command": "rm -rf /tmp/test", "execution_mode": "terminal"}
            },
        }

        with patch("gscripts.menubar.shortcuts.logger") as mock_logger:
            manager = ShortcutManager(config=config)

            # Should log warning
            mock_logger.warning.assert_called_once()
            assert "dangerous" in mock_logger.warning.call_args[0][0].lower()

            # But shortcut should still be loaded
            shortcuts = manager.get_shortcuts()
            assert "Dangerous" in shortcuts

    @pytest.mark.unit
    def test_execute_terminal_shortcut(self):
        """Test executing terminal mode shortcut"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Test": {"command": "gs status", "execution_mode": "terminal"}
            },
        }

        manager = ShortcutManager(config=config)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = manager.execute_shortcut("Test")

            assert result is True
            # Verify osascript was called
            mock_run.assert_called_once()
            args = mock_run.call_args[0][0]
            assert args[0] == "osascript"
            assert args[1] == "-e"
            assert "Terminal" in args[2]
            assert "gs status" in args[2]

    @pytest.mark.unit
    def test_execute_background_shortcut(self):
        """Test executing background mode shortcut"""
        from gscripts.menubar.shortcuts import ShortcutManager

        on_start = MagicMock()
        on_complete = MagicMock()

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Test": {"command": "echo 'test'", "execution_mode": "background"}
            },
        }

        manager = ShortcutManager(
            config=config, on_background_start=on_start, on_background_complete=on_complete
        )

        result = manager.execute_shortcut("Test")

        assert result is True
        # Verify start callback was called
        on_start.assert_called_once_with("Test", "echo 'test'")

        # Note: on_complete is called in background thread, not tested here

    @pytest.mark.unit
    def test_execute_nonexistent_shortcut(self):
        """Test executing non-existent shortcut returns False"""
        from gscripts.menubar.shortcuts import ShortcutManager

        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Test": {"command": "gs status", "execution_mode": "terminal"}
            },
        }

        manager = ShortcutManager(config=config)
        result = manager.execute_shortcut("NonExistent")

        assert result is False

    @pytest.mark.unit
    def test_reload_config(self):
        """Test reloading configuration"""
        from gscripts.menubar.shortcuts import ShortcutManager

        # Initial config
        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Old": {"command": "gs old", "execution_mode": "terminal"}
            },
        }

        manager = ShortcutManager(config=config)
        assert "Old" in manager.get_shortcuts()
        assert "New" not in manager.get_shortcuts()

        # Reload with new config
        new_config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "New": {"command": "gs new", "execution_mode": "background"}
            },
        }

        count = manager.reload_config(new_config)

        assert count == 1
        assert "Old" not in manager.get_shortcuts()
        assert "New" in manager.get_shortcuts()

    @pytest.mark.unit
    def test_reload_config_disabled_shortcuts(self):
        """Test reload with shortcuts disabled"""
        from gscripts.menubar.shortcuts import ShortcutManager

        # Initial config with shortcuts
        config = {
            "enable_shortcuts": True,
            "shortcuts": {
                "Test": {"command": "gs test", "execution_mode": "terminal"}
            },
        }

        manager = ShortcutManager(config=config)
        assert manager.is_enabled()

        # Reload with shortcuts disabled
        new_config = {"enable_shortcuts": False}
        count = manager.reload_config(new_config)

        assert count == 0
        assert not manager.is_enabled()
