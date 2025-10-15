"""
Tests for ConfigRepository
"""

import pytest
from pathlib import Path

from src.gscripts.infrastructure.persistence import ConfigRepository
from src.gscripts.infrastructure.filesystem import InMemoryFileSystem


@pytest.fixture
def mock_filesystem():
    """Provide mock filesystem"""
    return InMemoryFileSystem()


@pytest.fixture
def config_path():
    """Provide test config path"""
    return Path("/test/gs.json")


@pytest.fixture
def config_repository(mock_filesystem, config_path):
    """Provide config repository"""
    return ConfigRepository(mock_filesystem, config_path)


class TestConfigRepository:
    """Tests for ConfigRepository"""

    @pytest.mark.asyncio
    async def test_load_returns_empty_when_no_config(
        self,
        config_repository
    ):
        """Test load returns empty dict when config doesn't exist"""
        config = await config_repository.load()

        assert config == {}

    @pytest.mark.asyncio
    async def test_load_returns_config(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test load returns configuration"""
        # Create test config
        test_config = {
            "language": "en",
            "logging": {
                "level": "DEBUG"
            }
        }
        mock_filesystem.write_json(config_path, test_config)

        config = await config_repository.load()

        assert config == test_config

    @pytest.mark.asyncio
    async def test_save_writes_config(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test save writes configuration to file"""
        config = {
            "language": "zh",
            "show_examples": True
        }

        await config_repository.save(config)

        # Verify file was written
        assert mock_filesystem.exists(config_path)
        saved_config = mock_filesystem.read_json(config_path)
        assert saved_config == config

    @pytest.mark.asyncio
    async def test_get_returns_value_for_simple_key(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test get returns value for simple key"""
        mock_filesystem.write_json(config_path, {
            "language": "zh"
        })

        value = await config_repository.get("language")

        assert value == "zh"

    @pytest.mark.asyncio
    async def test_get_returns_value_for_nested_key(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test get returns value for nested key with dot notation"""
        mock_filesystem.write_json(config_path, {
            "logging": {
                "level": "INFO",
                "file": "/var/log/gs.log"
            }
        })

        value = await config_repository.get("logging.level")

        assert value == "INFO"

    @pytest.mark.asyncio
    async def test_get_returns_default_when_key_not_found(
        self,
        config_repository
    ):
        """Test get returns default when key not found"""
        value = await config_repository.get("nonexistent", "default_value")

        assert value == "default_value"

    @pytest.mark.asyncio
    async def test_set_creates_simple_key(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test set creates simple key"""
        await config_repository.set("language", "en")

        config = mock_filesystem.read_json(config_path)
        assert config["language"] == "en"

    @pytest.mark.asyncio
    async def test_set_creates_nested_key(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test set creates nested key with dot notation"""
        await config_repository.set("logging.level", "DEBUG")

        config = mock_filesystem.read_json(config_path)
        assert config["logging"]["level"] == "DEBUG"

    @pytest.mark.asyncio
    async def test_set_updates_existing_key(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test set updates existing key"""
        # Initial config
        mock_filesystem.write_json(config_path, {
            "language": "zh",
            "show_examples": False
        })

        await config_repository.set("language", "en")

        config = mock_filesystem.read_json(config_path)
        assert config["language"] == "en"
        assert config["show_examples"] is False  # Unchanged

    @pytest.mark.asyncio
    async def test_set_preserves_other_nested_values(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test set preserves other nested values"""
        # Initial config
        mock_filesystem.write_json(config_path, {
            "logging": {
                "level": "INFO",
                "file": "/var/log/gs.log"
            }
        })

        await config_repository.set("logging.level", "DEBUG")

        config = mock_filesystem.read_json(config_path)
        assert config["logging"]["level"] == "DEBUG"
        assert config["logging"]["file"] == "/var/log/gs.log"  # Preserved

    @pytest.mark.asyncio
    async def test_cache_is_used_for_repeated_loads(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test that cache is used for repeated loads"""
        # Create config
        mock_filesystem.write_json(config_path, {"language": "zh"})

        # First load
        config1 = await config_repository.load()

        # Modify file directly (bypass cache)
        mock_filesystem.write_json(config_path, {"language": "en"})

        # Second load - should use cache
        config2 = await config_repository.load()

        assert config1 == config2
        assert config2["language"] == "zh"  # Still cached value

    @pytest.mark.asyncio
    async def test_clear_cache_reloads_from_file(
        self,
        config_repository,
        mock_filesystem,
        config_path
    ):
        """Test clear_cache forces reload from file"""
        # Create config
        mock_filesystem.write_json(config_path, {"language": "zh"})

        # First load
        await config_repository.load()

        # Modify file
        mock_filesystem.write_json(config_path, {"language": "en"})

        # Clear cache
        config_repository.clear_cache()

        # Load again - should reload from file
        config = await config_repository.load()

        assert config["language"] == "en"
