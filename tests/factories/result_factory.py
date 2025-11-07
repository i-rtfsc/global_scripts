"""
Result factory for generating test CommandResult instances.

Provides factory methods for creating varied command results.
"""

from gscripts.models.result import CommandResult


class ResultFactory:
    """Factory for creating CommandResult instances in tests."""

    @classmethod
    def success(
        cls, output: str = "Success", exit_code: int = 0, **kwargs
    ) -> CommandResult:
        """
        Create successful command result.

        Args:
            output: Command output
            exit_code: Exit code (default 0)
            **kwargs: Additional attributes

        Returns:
            CommandResult with success=True
        """
        return CommandResult(
            success=True, output=output, error="", exit_code=exit_code, **kwargs
        )

    @classmethod
    def failure(
        cls,
        error: str = "Error occurred",
        exit_code: int = 1,
        output: str = "",
        **kwargs,
    ) -> CommandResult:
        """
        Create failed command result.

        Args:
            error: Error message
            exit_code: Exit code (default 1)
            output: Optional output before failure
            **kwargs: Additional attributes

        Returns:
            CommandResult with success=False
        """
        return CommandResult(
            success=False, output=output, error=error, exit_code=exit_code, **kwargs
        )

    @classmethod
    def timeout(cls, timeout_seconds: int = 30) -> CommandResult:
        """Create command result for timeout scenario."""
        return cls.failure(
            error=f"Command timed out after {timeout_seconds} seconds",
            exit_code=124,  # Standard timeout exit code
        )

    @classmethod
    def not_found(cls, command: str = "command") -> CommandResult:
        """Create command result for command not found scenario."""
        return cls.failure(
            error=f"{command}: command not found",
            exit_code=127,  # Standard not found exit code
        )

    @classmethod
    def permission_denied(cls, resource: str = "resource") -> CommandResult:
        """Create command result for permission denied scenario."""
        return cls.failure(
            error=f"Permission denied: {resource}",
            exit_code=126,
        )

    @classmethod
    def with_output(cls, output: str, error: str = "") -> CommandResult:
        """
        Create result with specific output.

        Determines success based on whether error is present.
        """
        return CommandResult(
            success=(not error),
            output=output,
            error=error,
            exit_code=0 if not error else 1,
        )
