"""
Unit Tests for PluginExecutor

Tests for security features and enhancements (Tasks 4.1-4.7):
- Command validation (forbidden patterns, length limits)
- Timeout enforcement
- Argument sanitization with shlex.quote()
- Concurrent execution limiting (semaphore)
- Observer notifications
"""

import pytest
import asyncio
import shlex
from typing import List, Dict, Any

from src.gscripts.application.services import PluginExecutor
from src.gscripts.models import CommandResult
from src.gscripts.plugins.interfaces import PluginEvent


# Mock Implementations
class MockPluginLoader:
    """Mock plugin loader for testing"""

    def __init__(self):
        self._loaded_plugins: Dict[str, Any] = {}

    def get_loaded_plugins(self) -> Dict[str, Any]:
        return self._loaded_plugins

    def add_plugin(self, name: str, functions: Dict[str, Any]) -> None:
        """Helper to add plugin with functions"""
        self._loaded_plugins[name] = {"functions": functions}


class MockProcessExecutor:
    """Mock process executor for testing"""

    def __init__(self):
        self.executed_commands: List[Dict[str, Any]] = []
        self.default_result = CommandResult(
            success=True, output="Mock output", exit_code=0
        )
        self.timeout_commands: List[str] = []  # Commands that should timeout

    async def execute_shell(
        self, command: str, timeout: int = 30, **kwargs
    ) -> CommandResult:
        """Mock shell execution"""
        self.executed_commands.append(
            {"command": command, "timeout": timeout, "kwargs": kwargs}
        )

        # Simulate timeout for specific commands
        if any(pattern in command for pattern in self.timeout_commands):
            await asyncio.sleep(timeout + 1)  # Simulate timeout
            return CommandResult(
                success=False,
                error=f"命令执行超时 (>{timeout}秒)",
                exit_code=-1,
                metadata={"timeout": True},
            )

        return self.default_result


class MockObserver:
    """Mock observer for testing event notifications"""

    def __init__(self):
        self.events = []

    def on_plugin_event(self, event_data) -> None:
        self.events.append(
            {
                "event": event_data.event,
                "plugin_name": event_data.plugin_name,
                "metadata": event_data.metadata,
            }
        )


# Fixtures
@pytest.fixture
def mock_loader():
    """Provide mock plugin loader"""
    return MockPluginLoader()


@pytest.fixture
def mock_executor():
    """Provide mock process executor"""
    return MockProcessExecutor()


@pytest.fixture
def plugin_executor(mock_loader, mock_executor):
    """Provide PluginExecutor instance"""
    return PluginExecutor(
        plugin_loader=mock_loader,
        process_executor=mock_executor,
        max_concurrent=5,
        default_timeout=30,
    )


# Tests for Command Validation (Task 4.1)
class TestCommandValidation:
    """Tests for command safety validation"""

    @pytest.mark.asyncio
    async def test_validate_command_rejects_dangerous_patterns(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing command with forbidden pattern
        THEN command is rejected before execution
        """
        # Setup: Add plugin with dangerous command
        mock_loader.add_plugin(
            "test_plugin",
            {
                "dangerous_func": {
                    "type": "config",
                    "command": "rm -rf /",  # Forbidden pattern
                }
            },
        )

        # Execute
        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "dangerous_func"
        )

        # Assert
        assert result.success is False
        assert "security policy" in result.error.lower()
        assert len(mock_executor.executed_commands) == 0  # Command not executed

    @pytest.mark.asyncio
    async def test_validate_command_rejects_excessive_length(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing command exceeding max length
        THEN command is rejected
        """
        # Setup: Create extremely long command (>1000 chars)
        long_command = "echo " + "A" * 2000
        mock_loader.add_plugin(
            "test_plugin", {"long_func": {"type": "config", "command": long_command}}
        )

        # Execute
        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "long_func"
        )

        # Assert
        assert result.success is False
        assert (
            "security policy" in result.error.lower()
            or "length limit" in result.error.lower()
        )
        assert len(mock_executor.executed_commands) == 0

    @pytest.mark.asyncio
    async def test_validate_command_allows_safe_commands(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing safe command
        THEN command passes validation and executes
        """
        # Setup: Safe command
        mock_loader.add_plugin(
            "test_plugin", {"safe_func": {"type": "config", "command": "ls -la"}}
        )

        # Execute
        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "safe_func"
        )

        # Assert
        assert result.success is True
        assert len(mock_executor.executed_commands) == 1


# Tests for Argument Sanitization (Task 4.2)
class TestArgumentSanitization:
    """Tests for argument sanitization with shlex.quote()"""

    @pytest.mark.asyncio
    async def test_sanitize_args_prevents_injection(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing command with malicious arguments
        THEN arguments are properly quoted/escaped
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin", {"test_func": {"type": "config", "command": "echo {args}"}}
        )

        # Execute with injection attempt (using safer examples that won't trigger forbidden patterns)
        malicious_args = ["; echo pwned", "$(whoami)", "`ls -la`"]
        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "test_func", args=malicious_args
        )

        # Assert: Arguments should be quoted
        executed_cmd = mock_executor.executed_commands[0]["command"]

        # Check that dangerous parts are quoted (shlex.quote wraps them)
        assert "'; echo pwned'" in executed_cmd or "'; echo pwned'" in executed_cmd
        assert "$(whoami)" not in executed_cmd or "'$(whoami)'" in executed_cmd
        assert "`ls -la`" not in executed_cmd or "'`ls -la`'" in executed_cmd

    @pytest.mark.asyncio
    async def test_sanitize_args_handles_special_characters(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN arguments contain special shell characters
        THEN they are properly escaped
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin",
            {"test_func": {"type": "config", "command": "grep {args} file.txt"}},
        )

        # Execute with special characters that won't trigger forbidden patterns
        special_args = ["test & echo hello", "test | grep", "test * wildcard"]
        await plugin_executor.execute_plugin_function(
            "test_plugin", "test_func", args=special_args
        )

        # Assert: Each arg should be individually quoted
        executed_cmd = mock_executor.executed_commands[0]["command"]

        # Verify shlex.quote was applied
        for arg in special_args:
            quoted_arg = shlex.quote(arg)
            assert quoted_arg in executed_cmd

    @pytest.mark.asyncio
    async def test_sanitize_args_preserves_safe_arguments(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN arguments are safe
        THEN they are passed through (possibly quoted but functionally same)
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin", {"test_func": {"type": "config", "command": "echo {args}"}}
        )

        # Execute with safe args
        safe_args = ["hello", "world", "123"]
        await plugin_executor.execute_plugin_function(
            "test_plugin", "test_func", args=safe_args
        )

        # Assert: Command executed successfully
        assert len(mock_executor.executed_commands) == 1


# Tests for Timeout Enforcement (Task 4.3)
class TestTimeoutEnforcement:
    """Tests for timeout enforcement"""

    @pytest.mark.asyncio
    async def test_timeout_passed_to_executor(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing with custom timeout
        THEN timeout is passed to process executor
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin", {"test_func": {"type": "config", "command": "sleep 1"}}
        )

        # Execute with custom timeout
        await plugin_executor.execute_plugin_function(
            "test_plugin", "test_func", timeout=60
        )

        # Assert
        assert mock_executor.executed_commands[0]["timeout"] == 60

    @pytest.mark.asyncio
    async def test_default_timeout_used_when_not_specified(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing without timeout parameter
        THEN default timeout is used
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin", {"test_func": {"type": "config", "command": "echo test"}}
        )

        # Execute without timeout
        await plugin_executor.execute_plugin_function("test_plugin", "test_func")

        # Assert: Default timeout (30s) should be used
        assert mock_executor.executed_commands[0]["timeout"] == 30

    @pytest.mark.asyncio
    async def test_timeout_for_shell_scripts(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing shell script with timeout
        THEN timeout is enforced
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin",
            {
                "script_func": {
                    "type": "shell",
                    "command": "long_running_function",
                    "shell_file": "/tmp/test.sh",
                }
            },
        )

        # Execute with timeout
        await plugin_executor.execute_plugin_function(
            "test_plugin", "script_func", timeout=15
        )

        # Assert
        assert mock_executor.executed_commands[0]["timeout"] == 15


# Tests for Concurrent Execution Limiting (Task 4.4)
class TestConcurrentExecutionLimiting:
    """Tests for semaphore-based concurrent execution limiting"""

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrent_execution(
        self, mock_loader, mock_executor
    ):
        """
        WHEN multiple executions run concurrently
        THEN semaphore limits to max_concurrent
        """
        # Create executor with max_concurrent=2
        executor = PluginExecutor(
            plugin_loader=mock_loader, process_executor=mock_executor, max_concurrent=2
        )

        # Setup plugin with slow execution
        mock_loader.add_plugin(
            "test_plugin", {"slow_func": {"type": "config", "command": "sleep 0.1"}}
        )

        # Track concurrent executions
        concurrent_count = 0
        max_concurrent_seen = 0

        original_execute = mock_executor.execute_shell

        async def tracked_execute(*args, **kwargs):
            nonlocal concurrent_count, max_concurrent_seen
            concurrent_count += 1
            max_concurrent_seen = max(max_concurrent_seen, concurrent_count)

            await asyncio.sleep(0.05)  # Simulate work
            result = await original_execute(*args, **kwargs)

            concurrent_count -= 1
            return result

        mock_executor.execute_shell = tracked_execute

        # Execute 5 tasks concurrently
        tasks = [
            executor.execute_plugin_function("test_plugin", "slow_func")
            for _ in range(5)
        ]

        await asyncio.gather(*tasks)

        # Assert: Max concurrent should not exceed 2
        assert max_concurrent_seen <= 2

    @pytest.mark.asyncio
    async def test_semaphore_releases_after_execution(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN execution completes
        THEN semaphore slot is released for next task
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin", {"test_func": {"type": "config", "command": "echo test"}}
        )

        # Execute multiple times sequentially
        for _ in range(10):
            result = await plugin_executor.execute_plugin_function(
                "test_plugin", "test_func"
            )
            assert result.success is True

        # If semaphore wasn't released, this would hang
        assert len(mock_executor.executed_commands) == 10


# Tests for Observer Notifications (Task 4.5)
class TestObserverNotifications:
    """Tests for observer pattern in executor"""

    @pytest.mark.asyncio
    async def test_observer_notified_on_execution(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN plugin function executes
        THEN observer receives EXECUTING and EXECUTED events
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin", {"test_func": {"type": "config", "command": "echo test"}}
        )

        observer = MockObserver()
        plugin_executor.register_observer(observer)

        # Execute
        await plugin_executor.execute_plugin_function("test_plugin", "test_func")

        # Assert
        assert len(observer.events) >= 2

        # Check EXECUTING event
        executing_events = [
            e for e in observer.events if e["event"] == PluginEvent.EXECUTING
        ]
        assert len(executing_events) == 1
        assert executing_events[0]["plugin_name"] == "test_plugin"

        # Check EXECUTED event
        executed_events = [
            e for e in observer.events if e["event"] == PluginEvent.EXECUTED
        ]
        assert len(executed_events) == 1
        assert executed_events[0]["metadata"]["success"] is True

    @pytest.mark.asyncio
    async def test_observer_notified_on_error(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN plugin execution fails
        THEN observer receives EXECUTED event with error
        """
        # Setup
        mock_executor.default_result = CommandResult(
            success=False, error="Command failed", exit_code=1
        )

        mock_loader.add_plugin(
            "test_plugin", {"fail_func": {"type": "config", "command": "false"}}
        )

        observer = MockObserver()
        plugin_executor.register_observer(observer)

        # Execute
        await plugin_executor.execute_plugin_function("test_plugin", "fail_func")

        # Assert
        executed_events = [
            e for e in observer.events if e["event"] == PluginEvent.EXECUTED
        ]
        assert len(executed_events) == 1
        assert executed_events[0]["metadata"]["success"] is False
        assert "error" in executed_events[0]["metadata"]

    def test_register_observer_prevents_duplicates(self, plugin_executor):
        """
        WHEN registering same observer twice
        THEN observer is only added once
        """
        observer = MockObserver()

        plugin_executor.register_observer(observer)
        plugin_executor.register_observer(observer)

        assert plugin_executor._observers.count(observer) == 1

    def test_unregister_observer(self, plugin_executor):
        """
        WHEN unregistering observer
        THEN observer is removed from list
        """
        observer = MockObserver()

        plugin_executor.register_observer(observer)
        plugin_executor.unregister_observer(observer)

        assert observer not in plugin_executor._observers


# Tests for Error Handling (Task 4.6)
class TestErrorHandling:
    """Tests for error handling in executor"""

    @pytest.mark.asyncio
    async def test_plugin_not_found_error(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing non-existent plugin
        THEN appropriate error is returned
        """
        result = await plugin_executor.execute_plugin_function(
            "nonexistent_plugin", "some_func"
        )

        assert result.success is False
        assert "not found" in result.error.lower()
        assert result.exit_code == 1
        assert len(mock_executor.executed_commands) == 0

    @pytest.mark.asyncio
    async def test_function_not_found_error(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing non-existent function
        THEN appropriate error is returned
        """
        mock_loader.add_plugin(
            "test_plugin", {"existing_func": {"type": "config", "command": "echo test"}}
        )

        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "nonexistent_func"
        )

        assert result.success is False
        assert "not found" in result.error.lower()
        assert "nonexistent_func" in result.error
        assert len(mock_executor.executed_commands) == 0

    @pytest.mark.asyncio
    async def test_unknown_function_type_error(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN function has unknown type
        THEN appropriate error is returned
        """
        mock_loader.add_plugin(
            "test_plugin",
            {"weird_func": {"type": "unknown_type", "command": "echo test"}},
        )

        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "weird_func"
        )

        assert result.success is False
        assert "unknown" in result.error.lower()
        assert len(mock_executor.executed_commands) == 0


# Integration Tests (Task 4.7)
class TestPluginExecutorIntegration:
    """Integration tests combining multiple features"""

    @pytest.mark.asyncio
    async def test_full_execution_workflow_with_validation(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN executing valid command with all features
        THEN command is validated, sanitized, timed, and executed
        """
        # Setup
        mock_loader.add_plugin(
            "test_plugin",
            {"full_test": {"type": "config", "command": "grep {args} /tmp/test.log"}},
        )

        observer = MockObserver()
        plugin_executor.register_observer(observer)

        # Execute with potentially dangerous args (will be sanitized) but won't trigger forbidden patterns
        result = await plugin_executor.execute_plugin_function(
            "test_plugin",
            "full_test",
            args=["pattern; echo pwned", "--color"],
            timeout=45,
        )

        # Assert all features worked
        assert result.success is True  # Execution succeeded
        assert len(mock_executor.executed_commands) == 1

        # Timeout was passed
        assert mock_executor.executed_commands[0]["timeout"] == 45

        # Arguments were sanitized (the whole argument is quoted together)
        cmd = mock_executor.executed_commands[0]["command"]
        # The arg should be quoted as a single unit
        assert "'pattern; echo pwned'" in cmd or '"pattern; echo pwned"' in cmd

        # Observers were notified
        assert len(observer.events) >= 2

    @pytest.mark.asyncio
    async def test_validation_blocks_execution_early(
        self, plugin_executor, mock_loader, mock_executor
    ):
        """
        WHEN command fails validation
        THEN execution is blocked and observer is notified of failure
        """
        # Setup dangerous command
        mock_loader.add_plugin(
            "test_plugin", {"dangerous": {"type": "config", "command": "rm -rf /"}}
        )

        observer = MockObserver()
        plugin_executor.register_observer(observer)

        # Execute
        result = await plugin_executor.execute_plugin_function(
            "test_plugin", "dangerous"
        )

        # Assert
        assert result.success is False
        assert "security policy" in result.error.lower()
        assert len(mock_executor.executed_commands) == 0  # Never executed

        # Observer should still be notified
        assert len(observer.events) >= 1
