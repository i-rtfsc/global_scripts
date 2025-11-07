"""
Tests for shell_utils

Tests shell detection and processing utilities.
"""

from unittest.mock import patch, Mock
import subprocess

from gscripts.utils.shell_utils import detect_current_shell


class TestDetectCurrentShell:
    """Tests for detect_current_shell function"""

    @patch.dict("os.environ", {"FISH_VERSION": "3.1.0"})
    def test_detect_fish_from_env_variable(self):
        """Test detecting fish shell from FISH_VERSION env variable"""
        # Act
        result = detect_current_shell()

        # Assert
        assert result == "fish"

    @patch.dict("os.environ", {"ZSH_VERSION": "5.8"}, clear=True)
    def test_detect_zsh_from_env_variable(self):
        """Test detecting zsh shell from ZSH_VERSION env variable"""
        # Act
        result = detect_current_shell()

        # Assert
        assert result == "zsh"

    @patch.dict("os.environ", {"BASH_VERSION": "5.0.17"}, clear=True)
    def test_detect_bash_from_env_variable(self):
        """Test detecting bash shell from BASH_VERSION env variable"""
        # Act
        result = detect_current_shell()

        # Assert
        assert result == "bash"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_detect_shell_from_ps_command(self, mock_getppid, mock_run):
        """Test detecting shell from ps command"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "bash 1000\n"
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "bash"
        mock_run.assert_called_once()

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_detect_shell_with_path_prefix(self, mock_getppid, mock_run):
        """Test detecting shell when ps returns path"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "/bin/zsh 1000\n"
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "zsh"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_detect_login_shell_with_dash_prefix(self, mock_getppid, mock_run):
        """Test detecting login shell with - prefix"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "-fish 1000\n"
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "fish"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_detect_shell_traverses_parent_processes(self, mock_getppid, mock_run):
        """Test that detection traverses parent processes"""
        # Arrange
        mock_getppid.return_value = 1234
        # First call returns python, second returns bash
        mock_result1 = Mock()
        mock_result1.returncode = 0
        mock_result1.stdout = "python 1000\n"

        mock_result2 = Mock()
        mock_result2.returncode = 0
        mock_result2.stdout = "bash 999\n"

        mock_run.side_effect = [mock_result1, mock_result2]

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "bash"
        assert mock_run.call_count == 2

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_ps_command_timeout(self, mock_getppid, mock_run):
        """Test handling of ps command timeout"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_run.side_effect = subprocess.TimeoutExpired("ps", 1)

        # Act
        result = detect_current_shell()

        # Assert
        # Should fallback to other methods or return unknown
        assert result in ["bash", "zsh", "fish", "sh", "unknown"]

    @patch.dict("os.environ", {"SHELL": "/bin/zsh"}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_fallback_to_shell_env_variable(self, mock_getppid, mock_run):
        """Test fallback to SHELL environment variable"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 1  # ps command fails
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "zsh"

    @patch.dict("os.environ", {"SHELL": "/usr/local/bin/fish"}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_shell_env_variable_with_full_path(self, mock_getppid, mock_run):
        """Test SHELL env variable with full path"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "fish"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    @patch("pwd.getpwuid")
    def test_fallback_to_pwd_module(self, mock_getpwuid, mock_getppid, mock_run):
        """Test fallback to pwd module on Unix systems"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        mock_pwd_entry = Mock()
        mock_pwd_entry.pw_shell = "/bin/bash"
        mock_getpwuid.return_value = mock_pwd_entry

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "bash"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    @patch("pwd.getpwuid", side_effect=KeyError())
    def test_returns_unknown_when_all_methods_fail(
        self, mock_getpwuid, mock_getppid, mock_run
    ):
        """Test returns 'unknown' when all detection methods fail"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "unknown"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_detect_sh_shell(self, mock_getppid, mock_run):
        """Test detecting sh shell"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "sh 1000\n"
        mock_run.return_value = mock_result

        # Act
        result = detect_current_shell()

        # Assert
        assert result == "sh"

    @patch.dict("os.environ", {}, clear=True)
    @patch("subprocess.run")
    @patch("os.getppid")
    def test_ps_command_not_found(self, mock_getppid, mock_run):
        """Test handling when ps command is not found"""
        # Arrange
        mock_getppid.return_value = 1234
        mock_run.side_effect = FileNotFoundError()

        # Act
        result = detect_current_shell()

        # Assert
        # Should fallback or return unknown
        assert result in ["bash", "zsh", "fish", "sh", "unknown"]
