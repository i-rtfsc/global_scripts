"""
Unit tests for CLI main entry point

Tests GlobalScriptsCLI initialization, command routing, and error handling.
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, AsyncMock, call
from pathlib import Path

from gscripts.models.result import CommandResult


@pytest.fixture
def mock_all_imports():
    """Mock all imports to isolate CLI tests"""
    with patch('gscripts.cli.main.setup_logging'), \
         patch('gscripts.cli.main.get_logger') as mock_logger, \
         patch('gscripts.cli.main.get_i18n_manager'), \
         patch('gscripts.cli.main.OutputFormatter'), \
         patch('gscripts.cli.main.GlobalConstants'), \
         patch('gscripts.cli.main.ConfigManager') as mock_config_mgr, \
         patch('gscripts.cli.main.RealFileSystem'), \
         patch('gscripts.cli.main.PluginRepository') as mock_repo, \
         patch('gscripts.cli.main.PluginLoader') as mock_loader, \
         patch('gscripts.cli.main.ProcessExecutor'), \
         patch('gscripts.cli.main.PluginService') as mock_svc, \
         patch('gscripts.cli.main.PluginExecutor') as mock_exec, \
         patch('gscripts.cli.main.CommandHandler') as mock_handler:

        # Setup config manager
        mock_cfg_instance = Mock()
        mock_cfg_instance.get_plugins_dir.return_value = Path("/tmp/plugins")
        mock_config_mgr.return_value = mock_cfg_instance

        # Setup logger
        mock_logger_instance = Mock()
        mock_logger.return_value = mock_logger_instance

        # Setup plugin service
        mock_svc_instance = Mock()
        mock_svc_instance.load_all_plugins = AsyncMock()
        mock_svc_instance.get_loaded_plugins.return_value = {}
        mock_svc.return_value = mock_svc_instance

        # Setup command handler
        mock_handler_instance = Mock()
        mock_handler_instance.handle_command = AsyncMock(
            return_value=CommandResult(success=True, output="Test output", exit_code=0)
        )
        mock_handler.return_value = mock_handler_instance

        yield {
            'config_mgr': mock_config_mgr,
            'cfg_instance': mock_cfg_instance,
            'svc': mock_svc,
            'svc_instance': mock_svc_instance,
            'handler': mock_handler,
            'handler_instance': mock_handler_instance,
        }


@pytest.mark.unit
class TestMainFunction:
    """Test main() entry point"""

    @patch('gscripts.cli.main.GlobalScriptsCLI')
    @patch('gscripts.cli.main.asyncio.run')
    @patch('gscripts.cli.main.set_correlation_id')
    @patch('gscripts.cli.main.correlation_id', return_value='test-corr-id')
    def test_main_executes_successfully(self, mock_corr_id, mock_set_corr, mock_asyncio, mock_cli_class):
        """Test main() executes without errors"""
        # Arrange
        from gscripts.cli.main import main
        mock_cli_instance = Mock()
        mock_cli_instance.run = AsyncMock()
        mock_cli_class.return_value = mock_cli_instance

        # Act
        main()

        # Assert
        mock_set_corr.assert_called_once_with(None)
        mock_corr_id.assert_called_once()
        mock_cli_class.assert_called_once()
        mock_asyncio.assert_called_once()

    @patch('gscripts.cli.main.GlobalScriptsCLI')
    @patch('gscripts.cli.main.asyncio.run', side_effect=Exception("Test error"))
    @patch('gscripts.cli.main.set_correlation_id')
    @patch('gscripts.cli.main.correlation_id', return_value='test-corr-id')
    def test_main_handles_exception(self, mock_corr_id, mock_set_corr, mock_asyncio, mock_cli_class):
        """Test main() handles exceptions and exits with code 1"""
        # Arrange
        from gscripts.cli.main import main

        # Act & Assert
        with pytest.raises(SystemExit) as exc_info:
            main()

        assert exc_info.value.code == 1

    @patch('gscripts.cli.main.GlobalScriptsCLI')
    @patch('gscripts.cli.main.asyncio.run')
    @patch('gscripts.cli.main.set_correlation_id')
    @patch('gscripts.cli.main.correlation_id', return_value='test-corr-id')
    @patch('sys.argv', ['gs', 'status'])
    def test_main_with_command_args(self, mock_corr_id, mock_set_corr, mock_asyncio, mock_cli_class):
        """Test main() with command line arguments"""
        # Arrange
        from gscripts.cli.main import main
        mock_cli_instance = Mock()
        mock_cli_instance.run = AsyncMock()
        mock_cli_class.return_value = mock_cli_instance

        # Act
        main()

        # Assert
        mock_cli_class.assert_called_once()
        mock_asyncio.assert_called_once()


@pytest.mark.unit
class TestShellFunctionHandler:
    """Test shell function handler creation"""

    @patch('gscripts.cli.main.GlobalScriptsCLI')
    @patch('gscripts.cli.main.set_correlation_id')
    @patch('gscripts.cli.main.correlation_id', return_value='test-corr-id')
    @patch.dict(os.environ, {'GS_LANGUAGE': 'en'})
    def test_create_shell_function_handler(self, mock_corr_id, mock_set_corr, mock_cli_class):
        """Test creating shell function handler"""
        # Arrange
        from gscripts.cli.main import create_shell_function_handler
        mock_cli_instance = Mock()
        mock_cli_instance.handle_shell_function = Mock()
        mock_cli_class.return_value = mock_cli_instance

        # Act
        handler = create_shell_function_handler()
        handler('test_func', 'arg1', 'arg2')

        # Assert
        mock_cli_class.assert_called_once_with(chinese=False)
        mock_cli_instance.handle_shell_function.assert_called_once_with('test_func', ['arg1', 'arg2'])

    @patch('gscripts.cli.main.GlobalScriptsCLI')
    @patch('gscripts.cli.main.set_correlation_id')
    @patch('gscripts.cli.main.correlation_id', return_value='test-corr-id')
    @patch.dict(os.environ, {'GS_LANGUAGE': 'zh'})
    def test_shell_handler_uses_chinese_language(self, mock_corr_id, mock_set_corr, mock_cli_class):
        """Test shell handler respects GS_LANGUAGE env var"""
        # Arrange
        from gscripts.cli.main import create_shell_function_handler
        mock_cli_instance = Mock()
        mock_cli_instance.handle_shell_function = Mock()
        mock_cli_class.return_value = mock_cli_instance

        # Act
        handler = create_shell_function_handler()
        handler('test_func')

        # Assert
        mock_cli_class.assert_called_once_with(chinese=True)
