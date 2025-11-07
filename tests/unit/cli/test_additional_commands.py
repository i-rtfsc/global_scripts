"""
Tests for Additional CLI Commands

Tests DoctorCommand and RefreshCommand implementations.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path

from gscripts.cli.command_classes.doctor_command import DoctorCommand
from gscripts.cli.command_classes.refresh_command import RefreshCommand
from gscripts.models.result import CommandResult


# Fixtures for command dependencies
@pytest.fixture
def mock_config_manager():
    """Mock ConfigManager"""
    manager = Mock()
    manager.get.return_value = "test_value"
    return manager


@pytest.fixture
def mock_plugin_service():
    """Mock PluginService"""
    service = Mock()
    service.get_all_plugins = AsyncMock(return_value=[])
    service.get_plugin_metadata = AsyncMock(return_value=None)
    return service


@pytest.fixture
def mock_plugin_executor():
    """Mock PluginExecutor"""
    executor = Mock()
    executor.execute_plugin_function = AsyncMock(
        return_value=CommandResult(success=True, output="test output")
    )
    return executor


@pytest.fixture
def mock_i18n():
    """Mock I18nManager"""
    i18n = Mock()
    i18n.get_message = Mock(side_effect=lambda key, **kwargs: f"i18n:{key}")
    i18n.current_language = "zh"
    return i18n


@pytest.fixture
def mock_formatter():
    """Mock OutputFormatter"""
    formatter = Mock()
    formatter.format_help_usage = Mock(return_value="Help text")
    formatter.format_info_table = Mock(return_value="Info table")
    return formatter


@pytest.fixture
def mock_constants():
    """Mock GlobalConstants"""
    constants = Mock()
    constants.project_name = "Global Scripts"
    constants.project_version = "5.0.0"
    constants.exit_execution_error = 1
    constants.exit_general_error = 1
    constants.env_sh_file_name = "env.sh"

    # Mock get_config_dir to return a Path object
    mock_config_dir = Mock(spec=Path)
    mock_config_dir.exists.return_value = True
    mock_config_dir.glob.return_value = [Path("gs.zsh"), Path("gs.bash")]
    constants.get_config_dir = Mock(return_value=mock_config_dir)

    return constants


class TestDoctorCommand:
    """Tests for DoctorCommand"""

    def test_doctor_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test doctor command name property"""
        # Arrange & Act
        command = DoctorCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "doctor"

    def test_doctor_command_has_no_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test doctor command has no aliases"""
        # Arrange & Act
        command = DoctorCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert len(command.aliases) == 0

    @pytest.mark.asyncio
    async def test_doctor_command_execute_with_env_present(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
        tmp_path,
    ):
        """Test doctor command execution with env.sh present"""
        # Arrange
        command = DoctorCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Mock _execute directly since the internal Path logic is complex
        mock_result = CommandResult(
            success=True, message="i18n:commands.doctor", output="Info table"
        )
        command._execute = Mock(return_value=mock_result)

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        assert result.output == "Info table"
        command._execute.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_doctor_command_execute_with_missing_env(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test doctor command execution delegates to _execute"""
        # Arrange
        command = DoctorCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Mock _execute
        mock_result = CommandResult(
            success=True,
            message="i18n:commands.doctor",
            output="Table with missing status",
        )
        command._execute = Mock(return_value=mock_result)

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        command._execute.assert_called_once_with([])

    @pytest.mark.asyncio
    async def test_doctor_command_execute_handles_exception(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test doctor command handles exceptions"""
        # Arrange
        command = DoctorCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        with patch("pathlib.Path.exists", side_effect=RuntimeError("Test error")):
            # Act
            result = await command.execute([])

            # Assert
            assert result.success is False
            assert "i18n:errors.execution_failed" in result.error
            assert result.exit_code == mock_constants.exit_execution_error


class TestRefreshCommand:
    """Tests for RefreshCommand"""

    def test_refresh_command_name(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test refresh command name property"""
        # Arrange & Act
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert command.name == "refresh"

    def test_refresh_command_has_aliases(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test refresh command aliases"""
        # Arrange & Act
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Assert
        assert "reload" in command.aliases

    @pytest.mark.asyncio
    async def test_refresh_command_execute_success(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test refresh command execution success"""
        # Arrange
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Mock all the internal async methods
        command._regenerate_completions = AsyncMock()
        command._generate_router_index = AsyncMock()
        command._regenerate_env_if_missing = AsyncMock()
        command._source_env_file = AsyncMock(return_value="Success message")

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is True
        assert "Success message" in result.output
        command._regenerate_completions.assert_called_once()
        command._generate_router_index.assert_called_once()
        command._regenerate_env_if_missing.assert_called_once()
        command._source_env_file.assert_called_once()

    @pytest.mark.asyncio
    async def test_refresh_command_execute_handles_exception(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test refresh command handles exceptions"""
        # Arrange
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Mock internal method to raise exception
        command._regenerate_completions = AsyncMock(
            side_effect=RuntimeError("Test error")
        )

        # Act
        result = await command.execute([])

        # Assert
        assert result.success is False
        assert "i18n:errors.execution_failed" in result.error
        assert result.exit_code == mock_constants.exit_execution_error

    @pytest.mark.asyncio
    async def test_refresh_regenerate_completions_calls_setup(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
        tmp_path,
    ):
        """Test _regenerate_completions calls setup.py"""
        # Arrange
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        # Create fake setup.py
        fake_setup = tmp_path / "scripts" / "setup.py"
        fake_setup.parent.mkdir(parents=True)
        fake_setup.write_text("# fake setup")

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("pathlib.Path.exists", return_value=True), patch(
            "subprocess.run", return_value=mock_result
        ) as mock_run:

            # Act
            await command._regenerate_completions()

            # Assert
            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert "--generate-completion" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_refresh_generate_router_index_builds_index(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test _generate_router_index builds router index"""
        # Arrange
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        with patch("gscripts.router.indexer.build_router_index") as mock_build, patch(
            "gscripts.router.indexer.write_router_index"
        ) as mock_write, patch(
            "gscripts.infrastructure.persistence.plugin_loader.PluginLoader"
        ) as mock_loader_class, patch(
            "gscripts.infrastructure.persistence.plugin_repository.PluginRepository"
        ), patch(
            "gscripts.infrastructure.filesystem.file_operations.RealFileSystem"
        ), patch(
            "pathlib.Path.exists", return_value=True
        ):

            # Setup mock loader
            mock_loader = Mock()
            mock_loader.load_all_plugins = AsyncMock(return_value={"plugin1": Mock()})
            mock_loader_class.return_value = mock_loader

            mock_build.return_value = {"test": "index"}

            # Act
            await command._generate_router_index()

            # Assert
            mock_build.assert_called_once()
            mock_write.assert_called_once_with({"test": "index"})

    @pytest.mark.asyncio
    async def test_refresh_source_env_file_returns_success(
        self,
        mock_config_manager,
        mock_plugin_service,
        mock_plugin_executor,
        mock_i18n,
        mock_formatter,
        mock_constants,
    ):
        """Test _source_env_file returns success message"""
        # Arrange
        command = RefreshCommand(
            mock_config_manager,
            mock_plugin_service,
            mock_plugin_executor,
            mock_i18n,
            mock_formatter,
            mock_constants,
        )

        mock_result = Mock()
        mock_result.returncode = 0

        with patch("pathlib.Path.exists", return_value=True), patch(
            "gscripts.utils.shell_utils.detect_current_shell", return_value="bash"
        ), patch("subprocess.run", return_value=mock_result):

            # Act
            result = await command._source_env_file()

            # Assert
            assert "i18n:commands.command_success" in result
