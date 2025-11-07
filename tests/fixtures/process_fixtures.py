"""
Process execution fixtures for testing.

Provides mock process executors and subprocess results.
"""

import pytest
from typing import List, Tuple
from unittest.mock import Mock, AsyncMock

from gscripts.models import CommandResult


@pytest.fixture
def mock_process_result() -> CommandResult:
    """Provide mock successful process execution result."""
    return CommandResult(
        success=True,
        output="Mock command output",
        error="",
        exit_code=0,
    )


@pytest.fixture
def mock_process_error_result() -> CommandResult:
    """Provide mock failed process execution result."""
    return CommandResult(
        success=False,
        output="",
        error="Mock error message",
        exit_code=1,
    )


@pytest.fixture
def mock_process_executor():
    """
    Provide mock process executor for testing.

    The mock returns successful results by default.
    Can be configured in tests as needed.
    """
    executor = AsyncMock()

    # Default: return success
    executor.execute.return_value = CommandResult(
        success=True,
        output="Mock output",
        error="",
        exit_code=0,
    )

    return executor


@pytest.fixture
def mock_subprocess_result():
    """
    Provide mock subprocess.CompletedProcess result.

    Use this when testing code that uses asyncio.create_subprocess_*.
    """
    mock = Mock()
    mock.returncode = 0
    mock.stdout = b"Mock stdout"
    mock.stderr = b""
    return mock


@pytest.fixture
def mock_subprocess_error_result():
    """Provide mock subprocess result for error case."""
    mock = Mock()
    mock.returncode = 1
    mock.stdout = b""
    mock.stderr = b"Mock error"
    return mock


class MockAsyncProcess:
    """Mock async process for testing subprocess execution."""

    def __init__(
        self,
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self.pid = 12345

    async def communicate(self) -> Tuple[bytes, bytes]:
        """Mock communicate method."""
        return self._stdout, self._stderr

    async def wait(self) -> int:
        """Mock wait method."""
        return self.returncode


@pytest.fixture
def mock_async_process():
    """
    Provide mock async process for subprocess testing.

    Returns a factory function that creates MockAsyncProcess instances.

    Usage:
        process = mock_async_process(returncode=0, stdout=b"output")
    """

    def _create(
        returncode: int = 0,
        stdout: bytes = b"",
        stderr: bytes = b"",
    ) -> MockAsyncProcess:
        return MockAsyncProcess(returncode, stdout, stderr)

    return _create


@pytest.fixture
def mock_command_whitelist() -> List[str]:
    """Provide mock command whitelist for security testing."""
    return [
        "echo",
        "cat",
        "ls",
        "grep",
        "git",
        "adb",
        "repo",
    ]


@pytest.fixture
def mock_command_blacklist() -> List[str]:
    """Provide mock command blacklist for security testing."""
    return [
        "rm -rf",
        "dd",
        "mkfs",
        ":(){ :|:& };:",  # Fork bomb
        "chmod 000",
    ]
