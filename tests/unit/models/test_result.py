"""
Tests for CommandResult model
"""

from gscripts.models.result import CommandResult
from tests.factories import ResultFactory


class TestCommandResult:
    """Tests for CommandResult dataclass"""

    def test_create_successful_result(self):
        """Test creating successful command result"""
        # Act
        result = CommandResult(
            success=True,
            output="Command succeeded",
            error="",
            exit_code=0,
        )

        # Assert
        assert result.success is True
        assert result.output == "Command succeeded"
        assert result.error == ""
        assert result.exit_code == 0

    def test_create_failed_result(self):
        """Test creating failed command result"""
        # Act
        result = CommandResult(
            success=False,
            output="",
            error="Command failed",
            exit_code=1,
        )

        # Assert
        assert result.success is False
        assert result.error == "Command failed"
        assert result.exit_code == 1

    def test_factory_creates_success_result(self):
        """Test ResultFactory creates success result"""
        # Act
        result = ResultFactory.success(output="Done")

        # Assert
        assert result.success is True
        assert result.output == "Done"
        assert result.exit_code == 0

    def test_factory_creates_failure_result(self):
        """Test ResultFactory creates failure result"""
        # Act
        result = ResultFactory.failure(error="Failed")

        # Assert
        assert result.success is False
        assert result.error == "Failed"
        assert result.exit_code == 1

    def test_factory_creates_timeout_result(self):
        """Test ResultFactory creates timeout result"""
        # Act
        result = ResultFactory.timeout(timeout_seconds=30)

        # Assert
        assert result.success is False
        assert "30 seconds" in result.error
        assert result.exit_code == 124

    def test_factory_creates_not_found_result(self):
        """Test ResultFactory creates command not found result"""
        # Act
        result = ResultFactory.not_found(command="test_cmd")

        # Assert
        assert result.success is False
        assert "test_cmd" in result.error
        assert "not found" in result.error
        assert result.exit_code == 127

    def test_factory_creates_permission_denied_result(self):
        """Test ResultFactory creates permission denied result"""
        # Act
        result = ResultFactory.permission_denied(resource="/test/file")

        # Assert
        assert result.success is False
        assert "Permission denied" in result.error
        assert "/test/file" in result.error

    def test_factory_with_output(self):
        """Test ResultFactory with_output method"""
        # Act
        result = ResultFactory.with_output(
            output="Some output",
            error="Some error",
        )

        # Assert
        assert result.success is False  # Has error
        assert result.output == "Some output"
        assert result.error == "Some error"

    def test_factory_with_output_no_error(self):
        """Test ResultFactory with_output without error"""
        # Act
        result = ResultFactory.with_output(output="Output only")

        # Assert
        assert result.success is True  # No error
        assert result.output == "Output only"
        assert result.error == ""
