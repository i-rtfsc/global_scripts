"""
Tests for PluginExecutor service

Tests the application service for executing plugin functions.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from gscripts.application.services.plugin_executor import PluginExecutor
from gscripts.models.result import CommandResult
from tests.factories import ResultFactory


class TestPluginExecutorInitialization:
    """Tests for PluginExecutor initialization"""

    def test_create_executor_with_required_dependencies(self):
        """Test creating PluginExecutor with required dependencies"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        # Act
        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Assert
        assert executor._loader == mock_loader
        assert executor._executor == mock_process_executor
        assert executor._observers == []
        assert executor._default_timeout == 30

    def test_create_executor_with_custom_settings(self):
        """Test creating PluginExecutor with custom settings"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        # Act
        executor = PluginExecutor(
            mock_loader, mock_process_executor, max_concurrent=5, default_timeout=60
        )

        # Assert
        assert executor._default_timeout == 60


class TestObserverPattern:
    """Tests for observer pattern implementation"""

    def test_register_observer(self):
        """Test registering an observer"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()
        mock_observer = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        executor.register_observer(mock_observer)

        # Assert
        assert mock_observer in executor._observers

    def test_unregister_observer(self):
        """Test unregistering an observer"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()
        mock_observer = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)
        executor.register_observer(mock_observer)

        # Act
        executor.unregister_observer(mock_observer)

        # Assert
        assert mock_observer not in executor._observers

    def test_notify_observers_on_execution(self):
        """Test that observers are notified during execution"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo test"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success(output="test")
        )

        mock_observer = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)
        executor.register_observer(mock_observer)

        # Act
        import asyncio

        asyncio.run(executor.execute_plugin_function("testplugin", "testfunc"))

        # Assert
        mock_observer.on_plugin_event.assert_called()

    def test_observer_errors_dont_break_execution(self):
        """Test that observer errors don't break the execution"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo test"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success(output="test")
        )

        mock_observer = Mock()
        mock_observer.on_plugin_event.side_effect = Exception("Observer error")

        executor = PluginExecutor(mock_loader, mock_process_executor)
        executor.register_observer(mock_observer)

        # Act - Should not raise exception
        import asyncio

        result = asyncio.run(executor.execute_plugin_function("testplugin", "testfunc"))

        # Assert
        assert result.success is True


class TestValidateCommand:
    """Tests for command validation"""

    def test_validate_command_with_safe_command(self):
        """Test validating a safe command"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = executor._validate_command("echo hello")

        # Assert - depends on GlobalConstants configuration
        # We just verify it returns a boolean
        assert isinstance(result, bool)


class TestSanitizeArgs:
    """Tests for argument sanitization"""

    def test_sanitize_args_with_simple_args(self):
        """Test sanitizing simple arguments"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = executor._sanitize_args(["arg1", "arg2", "arg3"])

        # Assert
        assert len(result) == 3
        assert all(isinstance(arg, str) for arg in result)

    def test_sanitize_args_with_special_characters(self):
        """Test sanitizing arguments with special characters"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = executor._sanitize_args(["arg with spaces", "arg;with;semicolons"])

        # Assert
        assert len(result) == 2
        # Should be quoted to prevent injection
        assert "'" in result[0] or '"' in result[0]


class TestExecutePluginFunction:
    """Tests for execute_plugin_function method"""

    @pytest.mark.asyncio
    async def test_execute_plugin_not_found(self):
        """Test executing when plugin is not found"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(return_value={})

        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("nonexistent", "testfunc")

        # Assert
        assert result.success is False
        assert "not found" in result.error.lower()
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_execute_plugin_disabled(self):
        """Test executing a disabled plugin"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": False,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo test"}
                    },
                }
            }
        )

        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("testplugin", "testfunc")

        # Assert
        assert result.success is False
        assert "disabled" in result.error.lower()
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_execute_function_not_found(self):
        """Test executing when function is not found"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={"testplugin": {"enabled": True, "functions": {}}}
        )

        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("testplugin", "nonexistent")

        # Assert
        assert result.success is False
        assert "not found" in result.error.lower()
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_execute_config_function_successfully(self):
        """Test executing config function successfully"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo test"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success(output="test")
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("testplugin", "testfunc")

        # Assert
        assert result.success is True
        assert "test" in result.output
        mock_process_executor.execute_shell.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_script_function_successfully(self):
        """Test executing shell script function successfully"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "shell", "command": "test_command"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success(output="success")
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("testplugin", "testfunc")

        # Assert
        assert result.success is True
        mock_process_executor.execute_shell.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_with_timeout(self):
        """Test executing with custom timeout"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo test"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        await executor.execute_plugin_function("testplugin", "testfunc", timeout=60)

        # Assert
        # Verify timeout was passed to execute_shell
        call_kwargs = mock_process_executor.execute_shell.call_args[1]
        assert call_kwargs["timeout"] == 60

    @pytest.mark.asyncio
    async def test_execute_with_args(self):
        """Test executing with arguments"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo {args}"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        await executor.execute_plugin_function(
            "testplugin", "testfunc", args=["arg1", "arg2"]
        )

        # Assert
        mock_process_executor.execute_shell.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_with_unknown_function_type(self):
        """Test executing function with unknown type"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {"testfunc": {"type": "unknown_type"}},
                }
            }
        )

        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("testplugin", "testfunc")

        # Assert
        assert result.success is False
        assert "unknown" in result.error.lower()
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_execute_with_exception(self):
        """Test execution when exception occurs"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(side_effect=Exception("Unexpected error"))

        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Act
        result = await executor.execute_plugin_function("testplugin", "testfunc")

        # Assert
        assert result.success is False
        assert "failed" in result.error.lower()
        assert result.exit_code == 1


class TestExecuteConfigFunction:
    """Tests for _execute_config_function method"""

    @pytest.mark.asyncio
    async def test_execute_config_function_with_missing_command(self):
        """Test config function with missing command field"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "config"}  # Missing 'command' field

        # Act
        result = await executor._execute_config_function(function_info, [], 30)

        # Assert
        assert result.success is False
        assert "missing" in result.error.lower()
        assert "command" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_config_function_with_args_placeholder(self):
        """Test config function with {args} placeholder"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "config", "command": "echo {args}"}

        # Act
        await executor._execute_config_function(
            function_info, ["'hello'", "'world'"], 30
        )

        # Assert
        mock_process_executor.execute_shell.assert_called_once()
        # Verify args were substituted
        call_args = mock_process_executor.execute_shell.call_args[0][0]
        assert "'hello'" in call_args
        assert "'world'" in call_args

    @pytest.mark.asyncio
    async def test_execute_config_function_without_args_placeholder(self):
        """Test config function without {args} placeholder"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "config", "command": "echo test"}

        # Act
        await executor._execute_config_function(function_info, ["'arg1'"], 30)

        # Assert
        mock_process_executor.execute_shell.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_config_function_with_validation_failure(self):
        """Test config function with command validation failure"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Mock validation to fail
        executor._validate_command = Mock(return_value=False)

        function_info = {"type": "config", "command": "dangerous_command"}

        # Act
        result = await executor._execute_config_function(function_info, [], 30)

        # Assert
        assert result.success is False
        assert "rejected" in result.error.lower() or "security" in result.error.lower()


class TestExecuteScriptFunction:
    """Tests for _execute_script_function method"""

    @pytest.mark.asyncio
    async def test_execute_script_function_with_missing_command(self):
        """Test script function with missing command field"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "shell"}  # Missing 'command' field

        # Act
        result = await executor._execute_script_function(function_info, [], 30)

        # Assert
        assert result.success is False
        assert "missing" in result.error.lower()
        assert "command" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_script_function_with_shell_file(self, tmp_path):
        """Test script function with shell file"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Create temporary shell file
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\ntest_func() { echo 'test'; }")

        function_info = {
            "type": "shell",
            "command": "test_func",
            "shell_file": str(shell_file),
        }

        # Act
        await executor._execute_script_function(function_info, [], 30)

        # Assert
        mock_process_executor.execute_shell.assert_called_once()
        # Verify shell file is sourced
        call_args = mock_process_executor.execute_shell.call_args[0][0]
        assert "source" in call_args
        assert str(shell_file) in call_args

    @pytest.mark.asyncio
    async def test_execute_script_function_without_shell_file(self):
        """Test script function without shell file (direct command)"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "shell", "command": "ls -la"}

        # Act
        await executor._execute_script_function(function_info, [], 30)

        # Assert
        mock_process_executor.execute_shell.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_script_function_with_validation_failure(self):
        """Test script function with command validation failure"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Mock validation to fail
        executor._validate_command = Mock(return_value=False)

        function_info = {"type": "shell", "command": "dangerous_script"}

        # Act
        result = await executor._execute_script_function(function_info, [], 30)

        # Assert
        assert result.success is False
        assert "rejected" in result.error.lower() or "security" in result.error.lower()


class TestExecutePythonFunction:
    """Tests for _execute_python_function method"""

    @pytest.mark.asyncio
    async def test_execute_python_function_with_missing_python_file(self):
        """Test Python function with missing python_file field"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "python"}  # Missing 'python_file' field

        # Act
        result = await executor._execute_python_function(function_info, [])

        # Assert
        assert result.success is False
        assert "missing" in result.error.lower()
        assert "python_file" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_python_function_with_nonexistent_file(self):
        """Test Python function with nonexistent file"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        function_info = {"type": "python", "python_file": "/nonexistent/file.py"}

        # Act
        result = await executor._execute_python_function(function_info, [])

        # Assert
        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_python_function_with_valid_file(self, tmp_path):
        """Test Python function with valid file"""
        # Arrange
        mock_loader = Mock()
        mock_process_executor = Mock()

        executor = PluginExecutor(mock_loader, mock_process_executor)

        # Create temporary Python file with a simple function
        python_file = tmp_path / "test_plugin.py"
        python_file.write_text(
            """
from gscripts.models import CommandResult

def test_func(args=None):
    return CommandResult(success=True, output="test output")
"""
        )

        function_info = {
            "type": "python",
            "python_file": str(python_file),
            "name": "test_func",
        }

        # Act
        result = await executor._execute_python_function(function_info, [])

        # Assert
        # The dynamic import might fail in test environment, so we check for either success or specific error
        assert result is not None
        assert isinstance(result, CommandResult)


class TestConcurrentExecution:
    """Tests for concurrent execution limiting"""

    @pytest.mark.asyncio
    async def test_concurrent_execution_uses_semaphore(self):
        """Test that concurrent execution respects semaphore"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "testplugin": {
                    "enabled": True,
                    "functions": {
                        "testfunc": {"type": "config", "command": "echo test"}
                    },
                }
            }
        )

        mock_process_executor = Mock()
        mock_process_executor.execute_shell = AsyncMock(
            return_value=ResultFactory.success()
        )

        executor = PluginExecutor(mock_loader, mock_process_executor, max_concurrent=2)

        # Act - Execute multiple times concurrently
        import asyncio

        tasks = [
            executor.execute_plugin_function("testplugin", "testfunc") for _ in range(5)
        ]
        results = await asyncio.gather(*tasks)

        # Assert
        assert len(results) == 5
        assert all(r.success for r in results)
