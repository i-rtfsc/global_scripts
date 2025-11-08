"""
Unit tests for menubar utils module
"""

import os
import signal
import subprocess
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

# Only run these tests on macOS or if explicitly requested
pytestmark = pytest.mark.skipif(
    os.sys.platform != "darwin" and not os.getenv("FORCE_MENUBAR_TESTS"),
    reason="Menubar utils tests only run on macOS",
)


@pytest.fixture
def temp_pid_file(tmp_path):
    """Provide temporary PID file path"""
    config_dir = tmp_path / ".config" / "global-scripts"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "menubar.pid"


class TestProcessManagement:
    """Tests for process management functions"""

    @pytest.mark.unit
    def test_get_pid_file(self):
        """Test get_pid_file returns correct path"""
        from gscripts.menubar.utils import get_pid_file

        pid_file = get_pid_file()

        assert isinstance(pid_file, Path)
        assert pid_file.name == "menubar.pid"
        assert "global-scripts" in str(pid_file)

    @pytest.mark.unit
    def test_is_menubar_running_no_pid_file(self, temp_pid_file):
        """Test is_menubar_running when PID file doesn't exist"""
        from gscripts.menubar.utils import is_menubar_running

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            result = is_menubar_running()

            assert result is False

    @pytest.mark.unit
    def test_is_menubar_running_invalid_pid_file(self, temp_pid_file):
        """Test is_menubar_running with invalid PID file content"""
        from gscripts.menubar.utils import is_menubar_running

        temp_pid_file.write_text("not_a_number")

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            result = is_menubar_running()

            assert result is False

    @pytest.mark.unit
    def test_is_menubar_running_stale_pid(self, temp_pid_file):
        """Test is_menubar_running cleans up stale PID file"""
        from gscripts.menubar.utils import is_menubar_running

        # Write PID for non-existent process
        temp_pid_file.write_text("999999")

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            result = is_menubar_running()

            assert result is False
            assert not temp_pid_file.exists()  # Stale PID file removed

    @pytest.mark.unit
    def test_is_menubar_running_valid_process(self, temp_pid_file):
        """Test is_menubar_running with valid running process"""
        from gscripts.menubar.utils import is_menubar_running

        # Use current process PID (definitely running)
        current_pid = os.getpid()
        temp_pid_file.write_text(str(current_pid))

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            result = is_menubar_running()

            assert result is True

    @pytest.mark.unit
    def test_start_menubar_already_running(self, temp_pid_file):
        """Test start_menubar when already running"""
        from gscripts.menubar.utils import start_menubar

        current_pid = os.getpid()
        temp_pid_file.write_text(str(current_pid))

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            result = start_menubar()

            assert result is True  # Returns True without starting new process

    @pytest.mark.unit
    def test_start_menubar_spawns_process(self, temp_pid_file, tmp_path):
        """Test start_menubar spawns new process"""
        from gscripts.menubar.utils import start_menubar

        mock_process = MagicMock()
        mock_process.pid = 12345

        log_dir = tmp_path / "logs"

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            with patch("gscripts.menubar.utils.is_menubar_running", return_value=False):
                with patch("subprocess.Popen", return_value=mock_process) as mock_popen:
                    with patch("pathlib.Path.home", return_value=tmp_path):
                        result = start_menubar()

                        assert result is True
                        mock_popen.assert_called_once()

                        # Verify correct command
                        args = mock_popen.call_args
                        cmd = args[0][0]
                        assert "python" in cmd[0] or "python3" in cmd[0]
                        assert "-m" in cmd
                        assert "gscripts.menubar" in cmd

    @pytest.mark.unit
    def test_start_menubar_handles_exception(self, temp_pid_file):
        """Test start_menubar handles exceptions gracefully"""
        from gscripts.menubar.utils import start_menubar

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            with patch("gscripts.menubar.utils.is_menubar_running", return_value=False):
                with patch("subprocess.Popen", side_effect=Exception("Test error")):
                    result = start_menubar()

                    assert result is False

    @pytest.mark.unit
    def test_stop_menubar_not_running(self, temp_pid_file):
        """Test stop_menubar when not running"""
        from gscripts.menubar.utils import stop_menubar

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            result = stop_menubar()

            assert result is True

    @pytest.mark.unit
    def test_stop_menubar_sends_sigterm(self, temp_pid_file):
        """Test stop_menubar sends SIGTERM"""
        from gscripts.menubar.utils import stop_menubar

        temp_pid_file.write_text("12345")

        with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
            with patch("os.kill") as mock_kill:
                # First call to check existence, second raises OSError (process gone)
                mock_kill.side_effect = [None, OSError()]

                result = stop_menubar(timeout=0.1)

                assert result is True
                # Should have called os.kill with SIGTERM
                calls = mock_kill.call_args_list
                assert any(call[0][1] == signal.SIGTERM for call in calls)

    @pytest.mark.unit
    def test_ensure_menubar_running_non_macos(self):
        """Test ensure_menubar_running on non-macOS platform"""
        from gscripts.menubar.utils import ensure_menubar_running

        with patch("sys.platform", "linux"):
            result = ensure_menubar_running({})

            assert result is False

    @pytest.mark.unit
    def test_ensure_menubar_running_disabled(self):
        """Test ensure_menubar_running when disabled in config"""
        from gscripts.menubar.utils import ensure_menubar_running

        config = {"menubar": {"enabled": False}}

        with patch("sys.platform", "darwin"):
            result = ensure_menubar_running(config)

            assert result is False

    @pytest.mark.unit
    def test_ensure_menubar_running_no_rumps(self, temp_pid_file):
        """Test ensure_menubar_running when rumps not installed"""
        from gscripts.menubar.utils import ensure_menubar_running

        config = {"menubar": {"enabled": True}}

        with patch("sys.platform", "darwin"):
            with patch("builtins.__import__", side_effect=ImportError("No rumps")):
                result = ensure_menubar_running(config)

                assert result is False

    @pytest.mark.unit
    def test_ensure_menubar_running_starts_if_needed(self, temp_pid_file):
        """Test ensure_menubar_running starts menu bar if enabled"""
        from gscripts.menubar.utils import ensure_menubar_running

        config = {"menubar": {"enabled": True}}

        with patch("sys.platform", "darwin"):
            with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
                with patch("gscripts.menubar.utils.is_menubar_running", return_value=False):
                    with patch("gscripts.menubar.utils.start_menubar", return_value=True) as mock_start:
                        result = ensure_menubar_running(config)

                        assert result is True
                        mock_start.assert_called_once()

    @pytest.mark.unit
    def test_ensure_menubar_running_reuses_existing(self, temp_pid_file):
        """Test ensure_menubar_running reuses existing process"""
        from gscripts.menubar.utils import ensure_menubar_running

        config = {"menubar": {"enabled": True}}

        with patch("sys.platform", "darwin"):
            with patch("gscripts.menubar.utils.get_pid_file", return_value=temp_pid_file):
                with patch("gscripts.menubar.utils.is_menubar_running", return_value=True):
                    with patch("gscripts.menubar.utils.start_menubar") as mock_start:
                        result = ensure_menubar_running(config)

                        assert result is True
                        mock_start.assert_not_called()  # Should not start new process
