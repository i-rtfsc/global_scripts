"""
Tests for ConfigService

Tests the application service for configuration management.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from gscripts.application.services.config_service import ConfigService


class TestConfigServiceInitialization:
    """Tests for ConfigService initialization"""

    def test_create_service_with_required_dependencies(self):
        """Test creating ConfigService with required dependencies"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()

        # Act
        service = ConfigService(mock_repository, mock_environment)

        # Assert
        assert service._repository == mock_repository
        assert service._environment == mock_environment
        assert service._defaults is not None
        assert isinstance(service._defaults, dict)

    def test_create_service_with_custom_defaults(self):
        """Test creating ConfigService with custom defaults"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        custom_defaults = {"custom_key": "custom_value"}

        # Act
        service = ConfigService(
            mock_repository, mock_environment, defaults=custom_defaults
        )

        # Assert
        assert service._defaults == custom_defaults

    def test_default_config_structure(self):
        """Test that default config has expected structure"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()

        # Act
        service = ConfigService(mock_repository, mock_environment)

        # Assert
        assert "language" in service._defaults
        assert "logging" in service._defaults
        assert "show_examples" in service._defaults
        assert "completion" in service._defaults
        assert "prompt" in service._defaults


class TestGetConfiguration:
    """Tests for get method with cascading lookup"""

    @pytest.mark.asyncio
    async def test_get_from_environment_variable(self):
        """Test getting value from environment variable (highest priority)"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        mock_environment.get = Mock(return_value="env_value")

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("test_key")

        # Assert
        assert result == "env_value"
        mock_environment.get.assert_called_once_with("GS_TEST_KEY")

    @pytest.mark.asyncio
    async def test_get_from_config_file_when_no_env(self):
        """Test getting value from config file when env var not set"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value="file_value")
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("test_key")

        # Assert
        assert result == "file_value"
        mock_repository.get.assert_called_once_with("test_key")

    @pytest.mark.asyncio
    async def test_get_with_provided_default(self):
        """Test getting value with provided default"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("test_key", default="provided_default")

        # Assert
        assert result == "provided_default"

    @pytest.mark.asyncio
    async def test_get_from_builtin_defaults(self):
        """Test getting value from built-in defaults"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("language")

        # Assert
        assert result == "zh"  # Default language

    @pytest.mark.asyncio
    async def test_get_with_dot_notation(self):
        """Test getting nested value with dot notation"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("logging.level")

        # Assert
        assert result == "INFO"  # Default logging level

    @pytest.mark.asyncio
    async def test_get_nonexistent_key_returns_none(self):
        """Test getting nonexistent key returns None"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("nonexistent.key")

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_get_env_key_conversion(self):
        """Test that key is converted correctly for env lookup"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        mock_environment.get = Mock(return_value="value")

        service = ConfigService(mock_repository, mock_environment)

        # Act
        await service.get("logging.level")

        # Assert
        # Verify env key was converted: logging.level -> GS_LOGGING_LEVEL
        mock_environment.get.assert_called_once_with("GS_LOGGING_LEVEL")


class TestSetConfiguration:
    """Tests for set method"""

    @pytest.mark.asyncio
    async def test_set_configuration_value(self):
        """Test setting configuration value"""
        # Arrange
        mock_repository = Mock()
        mock_repository.set = AsyncMock()
        mock_environment = Mock()

        service = ConfigService(mock_repository, mock_environment)

        # Act
        await service.set("test_key", "test_value")

        # Assert
        mock_repository.set.assert_called_once_with("test_key", "test_value")

    @pytest.mark.asyncio
    async def test_set_nested_configuration(self):
        """Test setting nested configuration with dot notation"""
        # Arrange
        mock_repository = Mock()
        mock_repository.set = AsyncMock()
        mock_environment = Mock()

        service = ConfigService(mock_repository, mock_environment)

        # Act
        await service.set("logging.level", "DEBUG")

        # Assert
        mock_repository.set.assert_called_once_with("logging.level", "DEBUG")


class TestGetAll:
    """Tests for get_all method"""

    @pytest.mark.asyncio
    async def test_get_all_merges_with_defaults(self):
        """Test that get_all merges file config with defaults"""
        # Arrange
        mock_repository = Mock()
        mock_repository.load = AsyncMock(return_value={"custom_key": "custom_value"})
        mock_environment = Mock()

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get_all()

        # Assert
        assert "custom_key" in result
        assert result["custom_key"] == "custom_value"
        # Should also contain defaults
        assert "language" in result

    @pytest.mark.asyncio
    async def test_get_all_with_empty_file_config(self):
        """Test get_all with empty file configuration"""
        # Arrange
        mock_repository = Mock()
        mock_repository.load = AsyncMock(return_value={})
        mock_environment = Mock()

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get_all()

        # Assert
        # Should return defaults
        assert "language" in result
        assert "logging" in result


class TestReload:
    """Tests for reload method"""

    @pytest.mark.asyncio
    async def test_reload_clears_cache(self):
        """Test that reload clears repository cache"""
        # Arrange
        mock_repository = Mock()
        mock_repository.clear_cache = Mock()
        mock_environment = Mock()

        service = ConfigService(mock_repository, mock_environment)

        # Act
        await service.reload()

        # Assert
        mock_repository.clear_cache.assert_called_once()


class TestParseEnvValue:
    """Tests for _parse_env_value method"""

    def test_parse_boolean_true_values(self):
        """Test parsing boolean true values"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        # Act & Assert
        assert service._parse_env_value("true") is True
        assert service._parse_env_value("TRUE") is True
        assert service._parse_env_value("yes") is True
        assert service._parse_env_value("1") is True

    def test_parse_boolean_false_values(self):
        """Test parsing boolean false values"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        # Act & Assert
        assert service._parse_env_value("false") is False
        assert service._parse_env_value("FALSE") is False
        assert service._parse_env_value("no") is False
        assert service._parse_env_value("0") is False

    def test_parse_integer_values(self):
        """Test parsing integer values"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        # Act & Assert
        assert service._parse_env_value("123") == 123
        assert service._parse_env_value("-456") == -456

    def test_parse_float_values(self):
        """Test parsing float values"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        # Act & Assert
        assert service._parse_env_value("3.14") == 3.14
        assert service._parse_env_value("-2.5") == -2.5

    def test_parse_string_values(self):
        """Test parsing string values"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        # Act & Assert
        assert service._parse_env_value("hello") == "hello"
        assert service._parse_env_value("test_value") == "test_value"


class TestMergeDicts:
    """Tests for _merge_dicts method"""

    def test_merge_simple_values(self):
        """Test merging simple key-value pairs"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        base = {"key1": "value1"}
        overlay = {"key2": "value2"}

        # Act
        service._merge_dicts(base, overlay)

        # Assert
        assert base["key1"] == "value1"
        assert base["key2"] == "value2"

    def test_merge_nested_dicts(self):
        """Test merging nested dictionaries"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        base = {"outer": {"inner1": "value1"}}
        overlay = {"outer": {"inner2": "value2"}}

        # Act
        service._merge_dicts(base, overlay)

        # Assert
        assert base["outer"]["inner1"] == "value1"
        assert base["outer"]["inner2"] == "value2"

    def test_merge_overwrites_non_dict_values(self):
        """Test that non-dict values are overwritten"""
        # Arrange
        mock_repository = Mock()
        mock_environment = Mock()
        service = ConfigService(mock_repository, mock_environment)

        base = {"key": "old_value"}
        overlay = {"key": "new_value"}

        # Act
        service._merge_dicts(base, overlay)

        # Assert
        assert base["key"] == "new_value"


class TestConvenienceMethods:
    """Tests for convenience methods"""

    @pytest.mark.asyncio
    async def test_get_language(self):
        """Test get_language convenience method"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get_language()

        # Assert
        assert result == "zh"  # Default

    @pytest.mark.asyncio
    async def test_get_logging_level(self):
        """Test get_logging_level convenience method"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get_logging_level()

        # Assert
        assert result == "INFO"  # Default

    @pytest.mark.asyncio
    async def test_get_show_examples(self):
        """Test get_show_examples convenience method"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get_show_examples()

        # Assert
        assert result is False  # Default

    @pytest.mark.asyncio
    async def test_get_prompt_theme(self):
        """Test get_prompt_theme convenience method"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get_prompt_theme()

        # Assert
        assert result == "bitstream"  # Default

    @pytest.mark.asyncio
    async def test_is_debug_mode_true(self):
        """Test is_debug_mode when logging level is DEBUG"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value="DEBUG")
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.is_debug_mode()

        # Assert
        assert result is True

    @pytest.mark.asyncio
    async def test_is_debug_mode_false(self):
        """Test is_debug_mode when logging level is not DEBUG"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.is_debug_mode()

        # Assert
        assert result is False


class TestConfigurationPriority:
    """Tests for configuration priority cascade"""

    @pytest.mark.asyncio
    async def test_environment_overrides_file(self):
        """Test that environment variable overrides file config"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value="file_value")
        mock_environment = Mock()
        mock_environment.get = Mock(return_value="env_value")

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("test_key")

        # Assert
        assert result == "env_value"
        # Should not call repository.get since env var was found
        mock_repository.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_file_overrides_default(self):
        """Test that file config overrides built-in default"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value="file_language")
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("language")

        # Assert
        assert result == "file_language"

    @pytest.mark.asyncio
    async def test_provided_default_overrides_builtin_default(self):
        """Test that provided default overrides built-in default"""
        # Arrange
        mock_repository = Mock()
        mock_repository.get = AsyncMock(return_value=None)
        mock_environment = Mock()
        mock_environment.get = Mock(return_value=None)

        service = ConfigService(mock_repository, mock_environment)

        # Act
        result = await service.get("language", default="en")

        # Assert
        assert result == "en"
