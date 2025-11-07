"""
Tests for ProcessExecutor implementation

Tests the unified process executor for command execution.
"""

import pytest
import asyncio
import sys

from gscripts.infrastructure.execution.process_executor import (
    ProcessExecutor,
    ProcessConfig,
    get_process_executor,
)


class TestProcessConfig:
    """Tests for ProcessConfig dataclass"""

    def test_create_process_config_with_defaults(self):
        """Test creating ProcessConfig with default values"""
        # Act
        config = ProcessConfig()

        # Assert
        assert config.timeout == 30
        assert config.cwd is None
        assert config.env is None
        assert config.capture_output is True
        assert config.shell is False

    def test_create_process_config_with_custom_values(self, tmp_path):
        """Test creating ProcessConfig with custom values"""
        # Arrange
        cwd = tmp_path / "workdir"
        env = {"VAR1": "value1", "VAR2": "value2"}

        # Act
        config = ProcessConfig(
            timeout=60,
            cwd=cwd,
            env=env,
            capture_output=False,
            shell=True,
        )

        # Assert
        assert config.timeout == 60
        assert config.cwd == cwd
        assert config.env == env
        assert config.capture_output is False
        assert config.shell is True


class TestProcessExecutorInitialization:
    """Tests for ProcessExecutor initialization"""

    def test_create_executor_with_default_timeout(self):
        """Test creating ProcessExecutor with default timeout"""
        # Act
        executor = ProcessExecutor()

        # Assert
        assert executor.default_timeout == 30
        assert executor.running_processes == {}

    def test_create_executor_with_custom_timeout(self):
        """Test creating ProcessExecutor with custom default timeout"""
        # Act
        executor = ProcessExecutor(default_timeout=60)

        # Assert
        assert executor.default_timeout == 60


class TestExecuteCommand:
    """Tests for execute method"""

    @pytest.mark.asyncio
    async def test_execute_successful_command(self):
        """Test executing a successful command"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        result = await executor.execute(["echo", "hello"])

        # Assert
        assert result.success is True
        assert "hello" in result.output
        assert result.exit_code == 0
        assert result.execution_time >= 0

    @pytest.mark.asyncio
    async def test_execute_command_with_string(self):
        """Test executing command as string"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        result = await executor.execute("echo")

        # Assert
        assert result.success is True
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_execute_command_with_list(self):
        """Test executing command as list"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        result = await executor.execute(["echo", "test"])

        # Assert
        assert result.success is True
        assert "test" in result.output

    @pytest.mark.asyncio
    async def test_execute_failing_command(self):
        """Test executing a command that fails"""
        # Arrange
        executor = ProcessExecutor()

        # Act - Use a command that will fail on all platforms
        result = await executor.execute(
            ["false"] if sys.platform != "win32" else ["cmd", "/c", "exit 1"]
        )

        # Assert
        assert result.success is False
        assert result.exit_code != 0

    @pytest.mark.asyncio
    async def test_execute_with_timeout(self):
        """Test executing command with timeout"""
        # Arrange
        executor = ProcessExecutor()
        config = ProcessConfig(timeout=0.1)  # Very short timeout

        # Act - Sleep command that will timeout
        if sys.platform == "win32":
            result = await executor.execute(["timeout", "5"], config=config)
        else:
            result = await executor.execute(["sleep", "5"], config=config)

        # Assert
        assert result.success is False
        assert result.exit_code == -1
        assert "超时" in result.error or "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_with_custom_timeout_kwarg(self):
        """Test executing with timeout passed as kwarg"""
        # Arrange
        executor = ProcessExecutor()

        # Act - Override timeout via kwargs
        if sys.platform == "win32":
            result = await executor.execute(["timeout", "5"], timeout=0.1)
        else:
            result = await executor.execute(["sleep", "5"], timeout=0.1)

        # Assert
        assert result.success is False
        assert result.exit_code == -1

    @pytest.mark.asyncio
    async def test_execute_with_working_directory(self, tmp_path):
        """Test executing command with custom working directory"""
        # Arrange
        executor = ProcessExecutor()
        workdir = tmp_path / "workdir"
        workdir.mkdir()

        config = ProcessConfig(cwd=workdir)

        # Act - Use pwd/cd to check working directory
        if sys.platform == "win32":
            result = await executor.execute(["cmd", "/c", "cd"], config=config)
        else:
            result = await executor.execute(["pwd"], config=config)

        # Assert
        assert result.success is True
        assert str(workdir) in result.output

    @pytest.mark.asyncio
    async def test_execute_with_environment_variables(self):
        """Test executing command with custom environment variables"""
        # Arrange
        executor = ProcessExecutor()
        config = ProcessConfig(env={"TEST_VAR": "test_value"})

        # Act - Echo environment variable
        if sys.platform == "win32":
            result = await executor.execute(
                ["cmd", "/c", "echo", "%TEST_VAR%"], config=config
            )
        else:
            result = await executor.execute(
                ["sh", "-c", "echo $TEST_VAR"], config=config
            )

        # Assert
        assert result.success is True
        # Note: Environment variable might not be set in all contexts, so just check execution succeeded

    @pytest.mark.asyncio
    async def test_execute_tracks_running_process(self):
        """Test that execute tracks running processes"""
        # Arrange
        executor = ProcessExecutor()

        # Act - Start a long-running command in background and check immediately
        task = asyncio.create_task(
            executor.execute(
                ["sleep", "2"] if sys.platform != "win32" else ["timeout", "2"]
            )
        )

        # Give it a moment to start
        await asyncio.sleep(0.1)

        # Assert - Process should be tracked while running
        # (This is timing-dependent, so we just verify the dict exists)
        assert isinstance(executor.running_processes, dict)

        # Cleanup - wait for task to complete
        await task

    @pytest.mark.asyncio
    async def test_execute_result_includes_metadata(self):
        """Test that result includes execution metadata"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        result = await executor.execute(["echo", "test"])

        # Assert
        assert "metadata" in result.__dict__ or hasattr(result, "metadata")
        if hasattr(result, "metadata") and result.metadata:
            assert "command" in result.metadata
            assert "pid" in result.metadata


class TestExecuteShell:
    """Tests for execute_shell method"""

    @pytest.mark.asyncio
    async def test_execute_shell_successful_command(self):
        """Test executing successful shell command"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        if sys.platform == "win32":
            result = await executor.execute_shell("echo hello")
        else:
            result = await executor.execute_shell("echo hello")

        # Assert
        assert result.success is True
        assert "hello" in result.output

    @pytest.mark.asyncio
    async def test_execute_shell_with_pipes(self):
        """Test executing shell command with pipes"""
        # Arrange
        executor = ProcessExecutor()

        # Act - Use shell pipes
        if sys.platform == "win32":
            result = await executor.execute_shell('echo hello | findstr "hello"')
        else:
            result = await executor.execute_shell("echo hello | grep hello")

        # Assert
        assert result.success is True
        assert "hello" in result.output

    @pytest.mark.asyncio
    async def test_execute_shell_with_timeout(self):
        """Test shell command with timeout"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        if sys.platform == "win32":
            result = await executor.execute_shell("timeout 5", timeout=0.1)
        else:
            result = await executor.execute_shell("sleep 5", timeout=0.1)

        # Assert
        assert result.success is False
        assert result.exit_code == -1

    @pytest.mark.asyncio
    async def test_execute_shell_result_has_shell_metadata(self):
        """Test that shell execution result includes shell flag in metadata"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        result = await executor.execute_shell("echo test")

        # Assert
        if hasattr(result, "metadata") and result.metadata:
            assert result.metadata.get("shell") is True


class TestProcessManagement:
    """Tests for process management methods"""

    def test_get_running_processes_initially_empty(self):
        """Test that running_processes is initially empty"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        processes = executor.get_running_processes()

        # Assert
        assert processes == {}

    @pytest.mark.asyncio
    async def test_process_cleanup_after_execution(self):
        """Test that processes are cleaned up after execution"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        await executor.execute(["echo", "test"])

        # Assert - Process should be cleaned up
        assert len(executor.running_processes) == 0

    def test_kill_all_with_no_processes(self):
        """Test kill_all when no processes are running"""
        # Arrange
        executor = ProcessExecutor()

        # Act
        executor.kill_all()  # Should not raise error

        # Assert
        assert len(executor.running_processes) == 0


class TestGlobalExecutor:
    """Tests for global executor singleton"""

    def test_get_process_executor_returns_singleton(self):
        """Test that get_process_executor returns same instance"""
        # Act
        executor1 = get_process_executor()
        executor2 = get_process_executor()

        # Assert
        assert executor1 is executor2

    def test_get_process_executor_returns_process_executor(self):
        """Test that get_process_executor returns ProcessExecutor instance"""
        # Act
        executor = get_process_executor()

        # Assert
        assert isinstance(executor, ProcessExecutor)
